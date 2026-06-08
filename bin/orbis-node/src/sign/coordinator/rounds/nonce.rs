use crate::constants::SIGN_COLLECTION_TIMEOUT;
use crate::helpers::helpers::{determine_ring_node_id_from_peer_id, is_self_peer_id, RingConfig};
use crate::sign::coordinator::SignCoordinator;
use crate::sign::error::{Result, SignError};
use crate::sign::messages::{NonceRequest, SignContext, SignMessage};
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
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
    /// Collect nonce commitments from all peers (FROST Round 1, initiator side)
    ///
    /// Returns the collected commitments and optionally our own signing state.
    /// The `context` is forwarded to each peer inside the `NonceRequest` so that
    /// responders can auth-check before generating their nonce.
    pub(crate) async fn collect_nonces(
        &self,
        request_id: &str,
        ring: &RingConfig,
        node_id: u32,
        self_in_list: bool,
        context: &SignContext,
        local_dist_key_share: Option<&DistKeyShare<Fr>>,
    ) -> Result<(Vec<(u32, S::NonceCommitment)>, Option<S::SigningState>)> {
        let nonce_request_id = format!("nonce-{}", request_id);
        let mut all_commitments: Vec<(u32, S::NonceCommitment)> = Vec::new();
        let mut local_signing_state: Option<S::SigningState> = None;
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // Generate our own nonces using the pre-loaded dist_key_share (same PSS
        // generation snapshot as pub_poly and the signing-round share).
        if self_in_list {
            if let Some(dist_key_share) = local_dist_key_share {
                let signer = S::new();
                let (commitment, state) = signer.generate_nonces(dist_key_share).map_err(|e| {
                    SignError::Crypto(format!("Local nonce generation failed: {}", e))
                })?;
                seen_node_ids.insert(node_id);
                all_commitments.push((node_id, commitment));
                local_signing_state = Some(state);
            }
        }

        // Build expected peers for nonce round (everyone except self)
        let nonce_expected_peers: Vec<String> = ring
            .peer_ids
            .iter()
            .filter(|pid| !is_self_peer_id(&self.app_state.network, pid))
            .cloned()
            .collect();

        // Initialize response collection for nonce round using existing SignResponseManager
        if !self
            .app_state
            .sign_response_state
            .init_response(nonce_request_id.clone(), &nonce_expected_peers)
            .await
        {
            return Err(SignError::ProtocolError(
                "Nonce response limit exceeded".to_string(),
            ));
        }

        let min_needed_from_network = ring.threshold.saturating_sub(all_commitments.len());

        // Send nonce requests to all peers concurrently
        let mut set = tokio::task::JoinSet::new();
        if min_needed_from_network > 0 {
            for peer_id_str in &ring.peer_ids {
                if is_self_peer_id(&self.app_state.network, peer_id_str) {
                    continue;
                }

                let nonce_req = SignMessage::NonceRequest(NonceRequest {
                    request_id: nonce_request_id.clone(),
                    from_node_id: node_id,
                    ring_pk: ring.ring_pk_bytes.clone(),
                    context: context.clone(),
                });

                let peer_id = peer_id_str.clone();
                let req_id = nonce_request_id.clone();
                let app_state = self.app_state.clone();

                set.spawn(async move {
                    let coordinator = SignCoordinator::<D, S>::new(app_state);
                    coordinator
                        .send_request_and_receive_response(&peer_id, nonce_req, &req_id)
                        .await
                });
            }
        }

        // Wait until we have enough deserializable nonce commitments or the
        // deadline fires. The signer trait does not expose a standalone
        // cryptographic verifier for round-1 commitments, so deserialization and
        // node-id dedupe are the strongest early validation available here.
        let mut successful_responses = 0usize;
        if min_needed_from_network > 0 {
            match tokio::time::timeout(SIGN_COLLECTION_TIMEOUT, async {
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(Some(response))) => {
                            let Some(expected_node_id) =
                                determine_ring_node_id_from_peer_id(&response.sender_peer_hex, ring)
                            else {
                                tracing::error!(
                                    sender_peer = %response.sender_peer_hex,
                                    "Sign Coordinator: accepted nonce response from peer outside ring"
                                );
                                continue;
                            };
                            if let Some(commitment) = Self::parse_peer_nonce_response(
                                response.message,
                                expected_node_id,
                                &mut seen_node_ids,
                            ) {
                                all_commitments.push(commitment);
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
                                "Nonce peer request failed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Nonce collection task failed");
                        }
                    }
                }
                Ok::<(), SignError>(())
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    self.app_state
                        .sign_response_state
                        .remove_response(&nonce_request_id)
                        .await;
                    return Err(e);
                }
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "Nonce collection timed out; proceeding with partial responses"
                    );
                }
            }
        }

        // Cancel any stragglers once we have enough commitments or stop waiting.
        drop(set);

        // Collect nonce responses, removing the entry atomically (no clone, cleanup implicit)
        let nonce_responses = self
            .app_state
            .sign_response_state
            .take_authenticated_responses(&nonce_request_id)
            .await
            .ok_or_else(|| {
                SignError::Timeout(format!(
                    "No nonce responses found for request {}",
                    nonce_request_id
                ))
            })?;

        for response in nonce_responses {
            let Some(expected_node_id) =
                determine_ring_node_id_from_peer_id(&response.sender_peer_hex, ring)
            else {
                tracing::error!(
                    sender_peer = %response.sender_peer_hex,
                    "Sign Coordinator: stored nonce response from peer outside ring"
                );
                continue;
            };
            if let Some(commitment) = Self::parse_peer_nonce_response(
                response.message,
                expected_node_id,
                &mut seen_node_ids,
            ) {
                all_commitments.push(commitment);
            }
        }

        // Sort commitments by participant ID for deterministic ordering
        all_commitments.sort_by_key(|(id, _)| *id);

        Ok((all_commitments, local_signing_state))
    }

    pub(crate) fn select_signing_commitments(
        commitments: &[(u32, S::NonceCommitment)],
        threshold: usize,
        preferred_node_id: Option<u32>,
    ) -> Result<Vec<(u32, S::NonceCommitment)>> {
        if commitments.len() < threshold {
            return Err(SignError::InsufficientShares {
                got: commitments.len(),
                need: threshold,
            });
        }

        let mut selected: Vec<(u32, S::NonceCommitment)> = Vec::with_capacity(threshold);
        if let Some(preferred) = preferred_node_id {
            if let Some((id, commitment)) = commitments.iter().find(|(id, _)| *id == preferred) {
                selected.push((*id, commitment.clone()));
            }
        }

        for (id, commitment) in commitments {
            if selected.len() == threshold {
                break;
            }
            if selected.iter().any(|(selected_id, _)| selected_id == id) {
                continue;
            }
            selected.push((*id, commitment.clone()));
        }

        selected.sort_by_key(|(id, _)| *id);
        Ok(selected)
    }
}
