//! Initiator-side threshold PET check.
//!
//! There is no separate "leader" concept here, exactly like PRE's own
//! reencryption round: whichever node received the external `StartPreRequest`
//! drives the check, fanning out directly to the whole ring committee and
//! computing its own contribution locally if it happens to be a member.

use super::PetCoordinator;
use crate::helpers::identity::{determine_session_node_id, is_self_peer_id, node_key_for_id};
use crate::helpers::node_routes::resolve_node_routes;
use crate::helpers::protocol_version::read_ring_for_route;
use crate::helpers::response_manager::ResponseInitOutcome;
use crate::pet::v0::attestation::{pet_share_signing_bytes, PetShareAttestation};
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::{PetCheckContext, PetCheckRequest, PetMessage};
use crate::ring_state::RingShareBundle;
use authz::vera::ValidWindow;
use bulletin::r#trait::DocumentPayload;
use common::blockchain::{sign_node_message_with_hex_key, verify_node_message};
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, Dkg, Pet, PriShare, PubShare};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::collections::HashSet;
use tokio::time::Duration;

/// Overall deadline for collecting threshold PET-check shares, mirroring
/// `PRE_COLLECTION_TIMEOUT`. A PET check runs at most once per PRE request
/// (never on a hot loop), so a generous bound is fine.
const PET_COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);

impl<D, P> PetCoordinator<D, P>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    P: Pet<ShareValue = Fr, PublicKey = G1Affine> + Send + Sync + 'static,
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
    pub async fn initiate_pet_check(
        &self,
        request_id: String,
        document: DocumentPayload,
        salt: Option<String>,
        audit_target_object_id: String,
        actor_id: String,
        valid_window: Option<ValidWindow>,
    ) -> Result<Vec<PetShareAttestation>> {
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
            salt,
        };
        // This node's own independent verification — matches
        // `Pet::verify_tag_knowledge`'s doc: "every PET participant,
        // including the initiator, must call this." The resulting `tag` is
        // reused below both for this node's own share (if it is a ring
        // member) and for the final threshold-match check.
        let (tag, _pet_pk_hex, digest) = self.verify_pet_check_request(&ctx).await?;

        let node_id_opt =
            determine_session_node_id(&self.app_state.node_key, &ring_payload.peer_node_keys);

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

        if let Some(node_id) = node_id_opt {
            let bundle =
                RingShareBundle::load_by_ring_key(&self.app_state.local_storage, &document.ring_id)
                    .map_err(|e| {
                        PetError::Storage(format!("Failed to load share bundle: {}", e))
                    })?;
            let pri_share: PriShare<Fr> =
                PriShare::from_bytes(&bundle.share_bytes).map_err(|e| {
                    PetError::Deserialization(format!("Failed to deserialize PET share: {}", e))
                })?;
            let partial = P::partial_pet_check(&pri_share.v, &tag).map_err(|e| {
                PetError::Crypto(format!("Failed to compute PET check share: {}", e))
            })?;
            let partial_bytes = CryptoSerialize::to_bytes(&partial).map_err(|e| {
                PetError::Serialization(format!("Failed to serialize PET check share: {}", e))
            })?;
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
            let signature = sign_node_message_with_hex_key(
                &signing_key_hex,
                &pet_share_signing_bytes(&digest, node_id, &partial_bytes),
            )
            .map_err(|e| PetError::Crypto(format!("failed to sign PET check share: {e}")))?;
            seen_node_ids.insert(node_id);
            shares.push(PubShare {
                i: node_id,
                v: partial,
            });
            attestations.push(PetShareAttestation {
                from_node_id: node_id,
                partial: partial_bytes,
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
                        Ok(Some(PetMessage::CheckResponse {
                            from_node_id,
                            partial,
                            signature,
                            ..
                        })) => {
                            if !seen_node_ids.insert(from_node_id) {
                                continue;
                            }
                            let Some(node_key) =
                                node_key_for_id(from_node_id, &ring_payload.peer_node_keys)
                            else {
                                tracing::warn!(
                                    peer = %peer_id,
                                    from_node_id,
                                    "PET Coordinator: dropping check share from an out-of-range node id"
                                );
                                continue;
                            };
                            let signing_bytes =
                                pet_share_signing_bytes(&digest, from_node_id, &partial);
                            if let Err(error) =
                                verify_node_message(&node_key, &signing_bytes, &signature)
                            {
                                tracing::warn!(
                                    peer = %peer_id,
                                    from_node_id,
                                    %error,
                                    "PET Coordinator: dropping check share with an invalid signature"
                                );
                                continue;
                            }
                            match G1Affine::from_bytes(&partial) {
                                Ok(parsed) => {
                                    shares.push(PubShare {
                                        i: from_node_id,
                                        v: parsed,
                                    });
                                    attestations.push(PetShareAttestation {
                                        from_node_id,
                                        partial,
                                        signature,
                                    });
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        peer = %peer_id,
                                        %error,
                                        "PET Coordinator: dropping malformed check share"
                                    );
                                }
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
