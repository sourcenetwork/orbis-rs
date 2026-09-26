//! Responder-side PET-check message handling.

use super::PetCoordinator;
use crate::pet::v0::attestation::PetCheckStatementContext;
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::{PetCheckRequest, PetMessage};
use crate::reporting::v0::types::ring_state_sha256;
use crate::ring_state::RingShareBundle;
use common::blockchain::sign_node_message_with_hex_key;
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, Pet, PriShare, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{SigShareInner, SignImpl, SignaturePoint};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub async fn handle_message(&self, message: PetMessage) -> Result<Option<PetMessage>> {
        match message {
            PetMessage::CheckRequest(req) => {
                tracing::info!(
                    request_id = %req.request_id,
                    from_node_id = req.from_node_id,
                    "PET Coordinator: Received CheckRequest"
                );
                self.handle_check_request(*req).await
            }
            PetMessage::CheckResponse { .. } => {
                // Responses are collected by the initiator, not here.
                Ok(None)
            }
            PetMessage::Error { request_id, error } => {
                tracing::error!(
                    request_id = %request_id,
                    error = %error,
                    "PET Coordinator: Received error"
                );
                Ok(None)
            }
        }
    }

    /// Handle a PET-check request (responder side): independently verify the
    /// request, load this node's own share of the ring's PET checking key,
    /// and reply with this node's threshold contribution and its
    /// accompanying per-share DLEQ proof.
    async fn handle_check_request(&self, req: PetCheckRequest) -> Result<Option<PetMessage>> {
        let PetCheckRequest {
            request_id,
            context: ctx,
            ..
        } = req;

        let (tag, _pet_pk_hex, _digest, ring_payload) = self.verify_pet_check_request(&ctx).await?;

        let bundle =
            RingShareBundle::load_by_ring_key(&self.app_state.local_storage, &ctx.document.ring_id)
                .map_err(|e| PetError::Storage(format!("Failed to load share bundle: {}", e)))?;
        let pri_share: PriShare<Fr> = PriShare::from_bytes(&bundle.share_bytes).map_err(|e| {
            PetError::Deserialization(format!("Failed to deserialize PET share: {}", e))
        })?;
        let node_id = pri_share.i;

        let reply = P::partial_pet_check(&pri_share.v, node_id, &tag)
            .map_err(|e| PetError::Crypto(format!("Failed to compute PET check share: {}", e)))?;
        let partial_bytes = CryptoSerialize::to_bytes(&reply.partial.v)
            .map_err(|e| PetError::Serialization(format!("Failed to serialize partial: {}", e)))?;
        let challenge_bytes = CryptoSerialize::to_bytes(&reply.challenge).map_err(|e| {
            PetError::Serialization(format!("Failed to serialize challenge: {}", e))
        })?;
        let proof_bytes = CryptoSerialize::to_bytes(&reply.proof)
            .map_err(|e| PetError::Serialization(format!("Failed to serialize proof: {}", e)))?;

        let signed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PetError::InvalidState(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        let statement_ctx = PetCheckStatementContext {
            chain_id: self.app_state.bulletin.chain_id(),
            ring_id: ctx.document.ring_id.clone(),
            ring_pk: ring_payload.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(&ring_payload),
            protocol_version: self.routes.version,
            object_id: ctx.object_id.clone(),
            salt: ctx.salt.clone(),
            crypto_backend: P::name(),
            document_inline: ctx.document_inline,
        };
        let statement = statement_ctx.statement_for(
            self.app_state.node_key.clone(),
            request_id.clone(),
            signed_at,
            node_id,
            partial_bytes.clone(),
            challenge_bytes.clone(),
            proof_bytes.clone(),
        );

        // Signed so this contribution is portable: a PRE peer that never received
        // it directly can still verify it came from this exact committee member —
        // see `attestation::PetShareAttestation`.
        let signing_key = self
            .app_state
            .local_storage
            .get_encrypted(LocalStorageKeys::NodeSigningKey)
            .map_err(|e| PetError::Storage(format!("failed to read node signing key: {e}")))?
            .ok_or_else(|| PetError::Storage("node signing key is not configured".to_string()))?;
        let signing_key_hex = String::from_utf8(signing_key.to_vec())
            .map_err(|e| PetError::Storage(format!("stored node signing key is not utf-8: {e}")))?;
        let signature =
            sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes())
                .map_err(|e| PetError::Crypto(format!("failed to sign PET check share: {e}")))?;

        Ok(Some(PetMessage::CheckResponse {
            request_id,
            from_node_id: node_id,
            partial: partial_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
            signed_at,
            signature,
        }))
    }
}
