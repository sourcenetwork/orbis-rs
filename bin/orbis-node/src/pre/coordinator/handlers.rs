use super::PreCoordinator;
use crate::constants::{MAX_JWT_BYTES, MAX_TOKEN_LIFETIME_SECS};
use crate::pre::error::{PreError, Result};
use crate::pre::helpers::{
    check_policy_access, decode_ring_pk, deserialize_secret, fetch_bulletin_payloads,
    validate_pre_claims, verify_encryption_binding,
};
use crate::pre::messages::{PreMessage, ReencryptRequest};
use crate::ring_state::RingShareBundle;
use authn::{resolve_jwt_did, BearerToken, PreClaims};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PriShare, ReencryptReply, Secret,
    ThresholdDealer,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use std::time::{SystemTime, UNIX_EPOCH};
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
    /// Handle an incoming PRE message
    ///
    /// Routes the message to the appropriate handler based on message type.
    pub async fn handle_message(&self, message: PreMessage) -> Result<Option<PreMessage>> {
        match message {
            PreMessage::ReencryptRequest(req) => {
                tracing::info!(
                    request_id = %req.request_id,
                    from_node_id = req.from_node_id,
                    "PRE Coordinator: Received ReencryptRequest"
                );
                // Note: from_node_id is not validated here (initiator may not be in ring).
                self.handle_reencrypt_request(req).await
            }
            PreMessage::ReencryptResponse { .. } => {
                tracing::debug!(
                    request_id = %message.request_id(),
                    "PRE Coordinator: Received ReencryptResponse"
                );
                // Responses are collected by initiate_reencryption, not here
                Ok(None)
            }
            PreMessage::Error { request_id, error } => {
                tracing::error!(
                    request_id = %request_id,
                    error = %error,
                    "PRE Coordinator: Received error"
                );
                Ok(None)
            }
        }
    }

    /// Handle a reencryption request (responder side)
    async fn handle_reencrypt_request(&self, req: ReencryptRequest) -> Result<Option<PreMessage>> {
        let ReencryptRequest {
            request_id,
            from_node_id,
            context: ctx,
        } = req;
        // Get current timestamp (needed for both auth and response)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PreError::Generic(format!("Failed to get timestamp: {}", e)))?
            .as_secs();

        let token: BearerToken<PreClaims> = resolve_jwt_did(
            &ctx.token_string,
            current_time,
            MAX_TOKEN_LIFETIME_SECS,
            MAX_JWT_BYTES,
        )
        .map_err(|e| PreError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        // 2. Authorize: Validate JWT claims match request fields
        validate_pre_claims(
            &token,
            &ctx.rdr_pk_bytes,
            &ctx.object_id,
            &ctx.namespace,
            &ctx.derivation,
            &ctx.salt,
        )?;

        let (document_payload, ring_payload) =
            fetch_bulletin_payloads(&*self.app_state.bulletin, &ctx.namespace, &ctx.object_id)
                .await?;

        // Note: We do NOT validate from_node_id here because the reencrypt request initiator
        // may not be in the ring (external requesters use node_id=0).

        // Generate policy metadata for proof binding verification (before fields are moved)
        let policy_metadata = T::encode_metadata(
            &document_payload.policy_id,
            &document_payload.resource,
            &document_payload.permission,
            document_payload.tier.as_deref(),
            document_payload.timestamp,
            ctx.salt.as_deref(),
        );

        check_policy_access(
            &*self.app_state.authz,
            &document_payload,
            &ctx.object_id,
            &token.issuer_id,
            ctx.valid_window,
        )
        .await?;

        // 1. Deserialize the secret
        let secret = deserialize_secret(&document_payload.document)?;

        // 2. Deserialize reader public key
        let rdr_pk = <D::PublicKey>::from_bytes(&ctx.rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize ring public key to get the storage key
        let (_, ring_pk) = decode_ring_pk(&ring_payload.ring_pk)?;

        // 4. Load share bundle from local storage (single encrypted entry = atomic share+poly)
        let bundle = RingShareBundle::load(&self.app_state.local_storage, &ring_pk)
            .map_err(|e| PreError::Storage(format!("Failed to load share bundle: {}", e)))?;

        // 5. Deserialize final share from bundle
        let pri_share: PriShare<D::ShareValue> = PriShare::from_bytes(&bundle.share_bytes)
            .map_err(|e| {
                PreError::Deserialization(format!("Failed to deserialize final share: {}", e))
            })?;
        let node_id = pri_share.i;

        // 6. Create distributed key share
        let dist_key_share = DistKeyShare { pri_share };

        // 7. Perform reencryption
        let dealer = T::new();
        // Check permission binding - verify proof before re-encryption
        verify_encryption_binding(
            &ring_pk,
            ctx.derivation.as_deref(),
            document_payload.proof,
            &secret.enc_cmt,
            &policy_metadata,
        )?;
        let reply = dealer
            .reencrypt(&dist_key_share, &secret, &rdr_pk, ctx.derivation.as_deref())
            .map_err(|e| PreError::Crypto(format!("Reencryption failed: {}", e)))?;

        // 8. Serialize the reply components using trait methods
        let share_bytes = CryptoSerialize::to_bytes(&reply.share.v)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize share: {}", e)))?;

        let challenge_bytes = CryptoSerialize::to_bytes(&reply.challenge).map_err(|e| {
            PreError::Serialization(format!("Failed to serialize challenge: {}", e))
        })?;

        let proof_bytes = CryptoSerialize::to_bytes(&reply.proof)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize proof: {}", e)))?;

        // 9. Create response message
        let response = PreMessage::ReencryptResponse {
            request_id: request_id.clone(),
            from_node_id: node_id,
            share: share_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
        };

        tracing::debug!(
            request_id = %request_id,
            to_node_id = from_node_id,
            "PRE Coordinator: Sending ReencryptResponse"
        );

        Ok(Some(response))
    }
}
