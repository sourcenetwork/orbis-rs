//! Responder-side PET blind-equality-test message handling — commit, reveal,
//! and decrypt. Replaces the old single-round `CheckRequest`/`CheckResponse`
//! handler, which leaked information about the plaintext fingerprint across
//! repeated checks.
//!
//! Every handler independently re-authenticates and re-authorizes the exact
//! comparison from primary sources before releasing any crypto output —
//! copying an earlier phase's approval is insufficient.
//! These same three methods are also called directly (in-process, with this
//! node's own peer id) for the initiator's local contribution when it is
//! itself a ring member — see `coordinator::initiator` — so there is exactly
//! one code path for each phase's validation and crypto, live or local.

use super::verification::{build_and_verify_pet_blind_certificate, resolve_coordinator_node_key};
use super::PetCoordinator;
use crate::pet::v0::attestation::build_pet_blind_context;
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::{CommitRequest, DecryptRequest, PetMessage, RevealRequest};
use crate::pet::v0::pending_blind::PendingBlindingStoreOutcome;
use crate::reporting::v0::types::{
    pet_blind_commit_hash, pet_blind_proof_transcript_digest, pet_blind_selection_digest,
    PetBlindDecryptStatement, PetBlindRevealStatement, PET_BLIND_DECRYPT_RESPONSE_DOMAIN,
    PET_BLIND_REVEAL_RESPONSE_DOMAIN,
};
use crate::ring_state::RingShareBundle;
use common::blockchain::sign_node_message_with_hex_key;
use crypto::helpers::sample_scalar;
use crypto::r#trait::{CryptoSerialize, DistKeyShare, Dkg, Pet, PetTag, ThresholdSigner};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{SigShareInner, SignImpl, SignaturePoint};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::PeerId;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

fn current_unix_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PetError::InvalidState(format!("Failed to get timestamp: {}", e)))
        .map(|d| d.as_secs())
}

impl<D, P> PetCoordinator<D, P>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    P: Pet<ShareValue = Fr, PublicKey = G1Affine, PubPoly = D::PubPoly>,
    SignImpl: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = crypto::r#trait::PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    /// Route an incoming PET message.
    pub async fn handle_message(
        &self,
        message: PetMessage,
        peer_id: &PeerId,
    ) -> Result<Option<PetMessage>> {
        let request_id = message.request_id().to_owned();
        let result = match message {
            PetMessage::CommitRequest(req) => self.handle_commit_request(*req, peer_id).await,
            PetMessage::RevealRequest(req) => self.handle_reveal_request(*req, peer_id).await,
            PetMessage::DecryptRequest(req) => self.handle_decrypt_request(*req, peer_id).await,
            PetMessage::CommitResponse { .. }
            | PetMessage::RevealResponse { .. }
            | PetMessage::DecryptResponse { .. } => {
                // Responses are collected by the initiator, not here.
                Ok(None)
            }
            PetMessage::GenerationMismatch { .. } => Ok(None),
            PetMessage::Error { request_id, error } => {
                tracing::error!(
                    request_id = %request_id,
                    error = %error,
                    "PET Coordinator: Received error"
                );
                Ok(None)
            }
        };
        match result {
            Err(PetError::GenerationMismatch) => {
                Ok(Some(PetMessage::GenerationMismatch { request_id }))
            }
            other => other,
        }
    }

    fn signing_key_hex(&self) -> Result<String> {
        let signing_key = self
            .app_state
            .local_storage
            .get_encrypted(LocalStorageKeys::NodeSigningKey)
            .map_err(|e| PetError::Storage(format!("failed to read node signing key: {e}")))?
            .ok_or_else(|| PetError::Storage("node signing key is not configured".to_string()))?;
        String::from_utf8(signing_key.to_vec())
            .map_err(|e| PetError::Storage(format!("stored node signing key is not utf-8: {e}")))
    }

    /// Round 1 (Commit): independently verify the request, then generate and
    /// store a fresh blinding secret, replying with only its hiding
    /// commitment — nothing in a commitment alone reveals `z_i` or the
    /// blinded points, so there is nothing sensitive to withhold here.
    pub(crate) async fn handle_commit_request(
        &self,
        req: CommitRequest,
        peer_id: &PeerId,
    ) -> Result<Option<PetMessage>> {
        let CommitRequest {
            request_id,
            attempt_id,
            context: ctx,
            ..
        } = req;

        let (tag, pet_pk_hex, _digest, ring_payload) = self.verify_pet_check_request(&ctx).await?;
        let current_time = current_unix_time()?;
        let actor_id = super::verification::verify_pet_audit_authorization(
            &*self.app_state.authz,
            &ctx,
            ring_payload.trusted_auth_relay_dids.as_deref(),
            current_time,
        )
        .await?;
        let coordinator_node_key =
            resolve_coordinator_node_key(&self.app_state.bulletin, peer_id, &ring_payload).await?;

        let blind_context = build_pet_blind_context(
            self.app_state.bulletin.chain_id(),
            &ring_payload,
            &pet_pk_hex,
            self.routes.version,
            P::name(),
            &ctx,
            actor_id,
            coordinator_node_key,
            attempt_id.clone(),
        );
        let context_digest = blind_context.context_digest();

        let bundle = RingShareBundle::load_by_pet_ring_key(
            &self.app_state.local_storage,
            &ctx.document.ring_id,
        )
        .map_err(|e| PetError::Storage(format!("Failed to load share bundle: {}", e)))?;
        crate::pet::v0::generation::match_bundle::<D::PubPoly>(
            &bundle,
            &ctx.public_polynomial,
            ring_payload.threshold,
            &pet_pk_hex,
        )?;
        let pri_share = crate::pet::v0::generation::member_share::<D>(
            &bundle,
            &self.app_state.node_key,
            &ring_payload,
        )?;
        let node_id = pri_share.i;

        let target_fingerprint = P::owner_fingerprint(ctx.audit_target_object_id.as_bytes())
            .map_err(|e| PetError::Crypto(format!("Failed to compute owner fingerprint: {}", e)))?;

        // A fresh, independent blinding scalar per attempt — reusing one
        // across attempts would reintroduce a cancellation attack (the same
        // reason refresh/reshare must redistribute shares against a fresh
        // random polynomial, not reuse one). `sample_scalar` rather than
        // `generate_keypair`: only the scalar is needed here, and the
        // latter's matching public point would cost an unnecessary
        // variable-time scalar multiplication to compute.
        let z_i = sample_scalar()
            .map_err(|e| PetError::Crypto(format!("Failed to sample blinding scalar: {}", e)))?;

        // Throwaway digest: only the resulting points are used here. The
        // proof itself cannot be finalized until round 2, once
        // `selection_digest` is known — see `pending_blind`'s module doc
        // comment — so `challenge`/`proof` from this call are discarded and
        // recomputed for real at reveal time.
        let preliminary =
            P::prove_blinding_correctness(&z_i, &tag, &target_fingerprint, &[0u8; 32]).map_err(
                |e| PetError::Crypto(format!("Failed to compute blinding points: {}", e)),
            )?;
        let blinded_r_bytes = CryptoSerialize::to_bytes(&preliminary.blinded_r).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize blinded_r: {}", e))
        })?;
        let blinded_diff_bytes =
            CryptoSerialize::to_bytes(&preliminary.blinded_diff).map_err(|e| {
                PetError::Serialization(format!("Failed to serialize blinded_diff: {}", e))
            })?;

        let commit_salt: [u8; 32] = rand::random();
        let commitment = pet_blind_commit_hash(
            &attempt_id,
            &context_digest,
            node_id,
            &commit_salt,
            &blinded_r_bytes,
            &blinded_diff_bytes,
        );

        let store_outcome = self
            .app_state
            .pet_pending_blind
            .store(
                self.routes.version,
                &attempt_id,
                z_i,
                commit_salt,
                node_id,
                context_digest,
                commitment,
                peer_id.as_bytes().to_vec(),
            )
            .await;
        match store_outcome {
            PendingBlindingStoreOutcome::Stored => {}
            PendingBlindingStoreOutcome::AlreadyExists => {
                return Err(PetError::ProtocolError(format!(
                    "duplicate commit for attempt {attempt_id}"
                )));
            }
            PendingBlindingStoreOutcome::LimitReached => {
                return Err(PetError::ProtocolError(
                    "PET blinding pending-state limit reached".to_string(),
                ));
            }
        }

        Ok(Some(PetMessage::CommitResponse {
            request_id,
            attempt_id,
            context_digest,
            from_node_id: node_id,
            commitment: commitment.to_vec(),
        }))
    }

    /// Round 2 (Reveal): only ever sent to the exact `threshold`
    /// participants selected after round 1. Re-verifies everything from
    /// scratch, atomically consumes this node's pending secret, and replies
    /// with a fully signed opening plus its blinding-correctness proof.
    pub(crate) async fn handle_reveal_request(
        &self,
        req: RevealRequest,
        peer_id: &PeerId,
    ) -> Result<Option<PetMessage>> {
        let RevealRequest {
            request_id,
            attempt_id,
            all_commitments,
            context: ctx,
            ..
        } = req;

        let (tag, pet_pk_hex, _digest, ring_payload) = self.verify_pet_check_request(&ctx).await?;
        let current_time = current_unix_time()?;
        let actor_id = super::verification::verify_pet_audit_authorization(
            &*self.app_state.authz,
            &ctx,
            ring_payload.trusted_auth_relay_dids.as_deref(),
            current_time,
        )
        .await?;
        let coordinator_node_key =
            resolve_coordinator_node_key(&self.app_state.bulletin, peer_id, &ring_payload).await?;

        let bundle = RingShareBundle::load_by_pet_ring_key(
            &self.app_state.local_storage,
            &ctx.document.ring_id,
        )
        .map_err(PetError::Storage)?;
        crate::pet::v0::generation::match_bundle::<D::PubPoly>(
            &bundle,
            &ctx.public_polynomial,
            ring_payload.threshold,
            &pet_pk_hex,
        )?;
        let member = crate::pet::v0::generation::member_share::<D>(
            &bundle,
            &self.app_state.node_key,
            &ring_payload,
        )?;
        let threshold = ring_payload.threshold as usize;
        if all_commitments.len() != threshold {
            return Err(PetError::ProtocolError(format!(
                "reveal selected list has {} entries, ring threshold is {}",
                all_commitments.len(),
                threshold
            )));
        }
        let mut commitments_arr: Vec<(u32, [u8; 32])> = Vec::with_capacity(all_commitments.len());
        let mut seen_ids = HashSet::new();
        for (id, bytes) in &all_commitments {
            if !seen_ids.insert(*id) {
                return Err(PetError::ProtocolError(format!(
                    "duplicate node id {id} in selected list"
                )));
            }
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                PetError::Deserialization("selected-list commitment is not 32 bytes".to_string())
            })?;
            commitments_arr.push((*id, arr));
        }

        let blind_context = build_pet_blind_context(
            self.app_state.bulletin.chain_id(),
            &ring_payload,
            &pet_pk_hex,
            self.routes.version,
            P::name(),
            &ctx,
            actor_id,
            coordinator_node_key,
            attempt_id.clone(),
        );
        let context_digest = blind_context.context_digest();

        let pending = self
            .app_state
            .pet_pending_blind
            .take(self.routes.version, &attempt_id, peer_id.as_bytes())
            .await
            .ok_or_else(|| {
                PetError::ProtocolError(format!(
                    "no pending blinding state for attempt {attempt_id}"
                ))
            })?;

        if pending.node_id != member.i {
            return Err(PetError::GenerationMismatch);
        }
        if pending.context_digest != context_digest {
            return Err(PetError::ProtocolError(
                "reveal-phase context does not match the commit-phase context".to_string(),
            ));
        }

        let own_entries: Vec<_> = commitments_arr
            .iter()
            .filter(|(id, _)| *id == pending.node_id)
            .collect();
        if own_entries.len() != 1 || own_entries[0].1 != pending.commitment {
            return Err(PetError::ProtocolError(
                "selected list does not contain this node's original commitment exactly once"
                    .to_string(),
            ));
        }

        let selection_digest =
            pet_blind_selection_digest(&attempt_id, &context_digest, &commitments_arr);
        let blind_transcript_digest = pet_blind_proof_transcript_digest(
            &attempt_id,
            &context_digest,
            &selection_digest,
            pending.node_id,
            &pending.commitment,
        );

        let target_fingerprint = P::owner_fingerprint(ctx.audit_target_object_id.as_bytes())
            .map_err(|e| PetError::Crypto(format!("Failed to compute owner fingerprint: {}", e)))?;
        let reply = P::prove_blinding_correctness(
            &pending.z_i,
            &tag,
            &target_fingerprint,
            &blind_transcript_digest,
        )
        .map_err(|e| {
            PetError::Crypto(format!(
                "Failed to compute blinding-correctness proof: {}",
                e
            ))
        })?;

        let blinded_r_bytes = CryptoSerialize::to_bytes(&reply.blinded_r).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize blinded_r: {}", e))
        })?;
        let blinded_diff_bytes = CryptoSerialize::to_bytes(&reply.blinded_diff).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize blinded_diff: {}", e))
        })?;
        let challenge_bytes = CryptoSerialize::to_bytes(&reply.challenge).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize challenge: {}", e))
        })?;
        let proof_bytes = CryptoSerialize::to_bytes(&reply.proof)
            .map_err(|e| PetError::Serialization(format!("Failed to serialize proof: {}", e)))?;

        let signed_at = current_unix_time()?;
        let statement = PetBlindRevealStatement {
            domain: PET_BLIND_REVEAL_RESPONSE_DOMAIN.to_string(),
            chain_id: blind_context.chain_id.clone(),
            ring_id: blind_context.ring_id.clone(),
            ring_pk: blind_context.ring_pk.clone(),
            ring_state_sha256: blind_context.ring_state_sha256.clone(),
            protocol_version: blind_context.protocol_version,
            attempt_id: attempt_id.clone(),
            context_digest,
            selection_digest,
            responder_node_key: self.app_state.node_key.clone(),
            from_node_id: pending.node_id,
            commitment: pending.commitment.to_vec(),
            blinded_r: blinded_r_bytes.clone(),
            blinded_diff: blinded_diff_bytes.clone(),
            commit_salt: pending.commit_salt,
            challenge: challenge_bytes.clone(),
            proof: proof_bytes.clone(),
            signed_at,
        };
        let response_signature =
            sign_node_message_with_hex_key(&self.signing_key_hex()?, &statement.canonical_bytes())
                .map_err(|e| PetError::Crypto(format!("failed to sign PET reveal: {e}")))?;

        Ok(Some(PetMessage::RevealResponse {
            request_id,
            attempt_id,
            context_digest,
            selection_digest,
            from_node_id: pending.node_id,
            commitment: pending.commitment.to_vec(),
            blinded_r: blinded_r_bytes,
            blinded_diff: blinded_diff_bytes,
            commit_salt: pending.commit_salt,
            challenge: challenge_bytes,
            proof: proof_bytes,
            signed_at,
            response_signature,
        }))
    }

    /// Round 3 (Decrypt): independent of round 2's participant set. Verifies
    /// the complete certificate from scratch, then applies this node's
    /// ordinary threshold-decryption share to the certificate's aggregate
    /// ephemeral point — the same per-share DLEQ machinery as the old
    /// protocol, unchanged, just fed `Z·R` in place of `R`.
    pub(crate) async fn handle_decrypt_request(
        &self,
        req: DecryptRequest,
        peer_id: &PeerId,
    ) -> Result<Option<PetMessage>> {
        let DecryptRequest {
            request_id,
            attempt_id,
            certificate,
            context: ctx,
            ..
        } = req;

        let (tag, pet_pk_hex, _digest, ring_payload) = self.verify_pet_check_request(&ctx).await?;
        let current_time = current_unix_time()?;
        let actor_id = super::verification::verify_pet_audit_authorization(
            &*self.app_state.authz,
            &ctx,
            ring_payload.trusted_auth_relay_dids.as_deref(),
            current_time,
        )
        .await?;
        let coordinator_node_key =
            resolve_coordinator_node_key(&self.app_state.bulletin, peer_id, &ring_payload).await?;

        let blind_context = build_pet_blind_context(
            self.app_state.bulletin.chain_id(),
            &ring_payload,
            &pet_pk_hex,
            self.routes.version,
            P::name(),
            &ctx,
            actor_id,
            coordinator_node_key,
            attempt_id.clone(),
        );
        let context_digest = blind_context.context_digest();
        if certificate.attempt_id != attempt_id || certificate.context_digest != context_digest {
            return Err(PetError::ProtocolError(
                "certificate does not match this decrypt request's attempt/context".to_string(),
            ));
        }

        let target_fingerprint = P::owner_fingerprint(ctx.audit_target_object_id.as_bytes())
            .map_err(|e| PetError::Crypto(format!("Failed to compute owner fingerprint: {}", e)))?;
        let (aggregate_r, aggregate_diff) = build_and_verify_pet_blind_certificate::<D, P>(
            &certificate,
            &ring_payload,
            &tag,
            &target_fingerprint,
            &blind_context,
        )?;
        let certificate_digest = certificate.certificate_digest();

        let bundle = RingShareBundle::load_by_pet_ring_key(
            &self.app_state.local_storage,
            &ctx.document.ring_id,
        )
        .map_err(|e| PetError::Storage(format!("Failed to load share bundle: {}", e)))?;
        crate::pet::v0::generation::match_bundle::<D::PubPoly>(
            &bundle,
            &ctx.public_polynomial,
            ring_payload.threshold,
            &pet_pk_hex,
        )?;
        let pri_share = crate::pet::v0::generation::member_share::<D>(
            &bundle,
            &self.app_state.node_key,
            &ring_payload,
        )?;
        let node_id = pri_share.i;
        let public_polynomial_bytes = hex::decode(&bundle.public_polynomial).map_err(|e| {
            PetError::Deserialization(format!(
                "Failed to decode stored PET public polynomial: {}",
                e
            ))
        })?;

        let aggregate_r_bytes = CryptoSerialize::to_bytes(&aggregate_r).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize aggregate_r: {}", e))
        })?;
        let aggregate_diff_bytes = CryptoSerialize::to_bytes(&aggregate_diff).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize aggregate_diff: {}", e))
        })?;
        // Reuses the existing per-share decryption DLEQ unchanged, against
        // the certificate's aggregate `Z·R` in place of the old protocol's
        // bare `R`. `masked_fingerprint` is never read by `partial_pet_check`
        // — only `ephemeral_point` is.
        let synthetic_tag = PetTag {
            ephemeral_point: aggregate_r_bytes.clone(),
            masked_fingerprint: Vec::new(),
        };
        let reply = P::partial_pet_check(&pri_share.v, node_id, &synthetic_tag)
            .map_err(|e| PetError::Crypto(format!("Failed to compute PET decrypt share: {}", e)))?;
        // The unsafe-testing service targets a ring without changing its stored
        // bundle. All normal authorization, certificate and share checks above
        // still run. Sign the faulty proof so the report tests exercise genuine
        // attributable misbehavior rather than an invalid identity signature.
        #[cfg(feature = "unsafe-testing")]
        let reply = {
            let mut reply = reply;
            if self.app_state.pet_decrypt_fault.lock().await.as_deref()
                == Some(ctx.document.ring_id.as_str())
            {
                reply.proof += Fr::from(1u64);
            }
            reply
        };
        let partial_bytes = CryptoSerialize::to_bytes(&reply.partial.v)
            .map_err(|e| PetError::Serialization(format!("Failed to serialize partial: {}", e)))?;
        let challenge_bytes = CryptoSerialize::to_bytes(&reply.challenge).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize challenge: {}", e))
        })?;
        let proof_bytes = CryptoSerialize::to_bytes(&reply.proof)
            .map_err(|e| PetError::Serialization(format!("Failed to serialize proof: {}", e)))?;

        let signed_at = current_unix_time()?;
        let statement = PetBlindDecryptStatement {
            domain: PET_BLIND_DECRYPT_RESPONSE_DOMAIN.to_string(),
            chain_id: blind_context.chain_id.clone(),
            ring_id: blind_context.ring_id.clone(),
            ring_pk: blind_context.ring_pk.clone(),
            ring_state_sha256: blind_context.ring_state_sha256.clone(),
            protocol_version: blind_context.protocol_version,
            attempt_id: attempt_id.clone(),
            context_digest,
            certificate_digest,
            responder_node_key: self.app_state.node_key.clone(),
            from_node_id: node_id,
            aggregate_r: aggregate_r_bytes.clone(),
            aggregate_diff: aggregate_diff_bytes.clone(),
            partial: partial_bytes.clone(),
            challenge: challenge_bytes.clone(),
            proof: proof_bytes.clone(),
            signed_at,
            public_polynomial: public_polynomial_bytes.clone(),
        };
        let response_signature =
            sign_node_message_with_hex_key(&self.signing_key_hex()?, &statement.canonical_bytes())
                .map_err(|e| PetError::Crypto(format!("failed to sign PET decrypt share: {e}")))?;

        Ok(Some(PetMessage::DecryptResponse {
            request_id,
            attempt_id,
            context_digest,
            certificate_digest,
            from_node_id: node_id,
            aggregate_r: aggregate_r_bytes,
            aggregate_diff: aggregate_diff_bytes,
            partial: partial_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
            signed_at,
            public_polynomial: public_polynomial_bytes,
            response_signature,
        }))
    }
}
