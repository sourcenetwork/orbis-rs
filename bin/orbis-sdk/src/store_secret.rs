//! StoreSecret: posting a locally-encrypted document.

use authn::{create_authenticated_request, endpoints::store_secret::StoreSecretClaims};
#[cfg(feature = "webauthn")]
use orbis_integration_core::StoreSecretOperation;
use proto::v0::store_secret::store_secret_service_client::StoreSecretServiceClient;
use proto::v0::store_secret::{
    PetTagAttachment, StoreSecretRequest, StoreSecretResponse, WebAuthnAssertion,
};
use sha2::{Digest, Sha256};

use crate::client::OrbisClient;
use crate::crypto::{PreparedPetTag, PreparedSecret};
use crate::error::{Result, SdkError};
#[cfg(feature = "webauthn")]
use crate::evidence::{ChallengeEvidence, WireEvidence};
use crate::identity::JwtIdentitySigner;
use crate::jwt::{sign_jwt, JWT_TTL};

/// Result of a StoreSecret operation.
#[derive(Debug, Clone)]
pub struct StoreSecretResult {
    pub status: String,
    pub message: String,
    pub created_at: i64,
    pub object_id: String,
    pub ring_id: String,
    pub signature: String,
}

impl OrbisClient {
    /// Stores a prepared (pre-encrypted) secret, JWT-authenticated. This
    /// is idempotent — calling with the same [`PreparedSecret`] returns the
    /// same `object_id` without creating duplicates.
    ///
    /// `pet_tag` must be `Some` — from
    /// [`crate::crypto::prove_pet_tag_knowledge`] — for a `requires_pet`
    /// ring's document, and `None` otherwise.
    pub async fn store_prepared_secret_with_jwt(
        &self,
        prepared: &PreparedSecret,
        ring_id: String,
        signer: &impl JwtIdentitySigner,
        with_proof: bool,
        pet_tag: Option<&PreparedPetTag>,
    ) -> Result<StoreSecretResult> {
        let ctx = &prepared.context;
        let claims = StoreSecretClaims {
            encrypted_document_sha256: Sha256::digest(&prepared.encrypted_document).to_vec(),
            enc_cmt: prepared.enc_cmt.clone(),
            ring_id: ring_id.clone(),
            policy_id: ctx.policy_id.clone(),
            resource: ctx.resource.clone(),
            permission: ctx.permission.clone(),
            challenge: prepared.challenge.clone(),
            response: prepared.response.clone(),
            with_proof,
            tier: ctx.tier.clone(),
            timestamp: ctx.timestamp,
        };
        let (token, _metadata) = sign_jwt(signer, claims, JWT_TTL)?;

        let mut client = StoreSecretServiceClient::new(self.channel());
        let request = build_request(prepared, ring_id, with_proof, pet_tag, None);
        let tonic_request = create_authenticated_request(request, &token)
            .map_err(|e| SdkError::Crypto(format!("failed to attach JWT: {e}")))?;
        let response = client.store_secret(tonic_request).await?.into_inner();
        Ok(to_result(response))
    }

    /// Stores a prepared secret, authorized by evidence produced for a
    /// fresh [`StoreSecretOperation`] challenge instead of a JWT — e.g. a
    /// passkey asserting it is the document's own owner. Unlike
    /// Sign/PRE, StoreSecret's evidence has no earlier "pending" phase to
    /// build: nothing about the request depends on the evidence (there's
    /// no ephemeral key to generate up front), so the challenge is built
    /// and consumed in this one call.
    #[cfg(feature = "webauthn")]
    pub async fn store_prepared_secret_with_evidence<E>(
        &self,
        prepared: &PreparedSecret,
        ring_id: String,
        evidence: E,
        with_proof: bool,
        pet_tag: Option<&PreparedPetTag>,
    ) -> Result<StoreSecretResult>
    where
        E: ChallengeEvidence<StoreSecretOperation>,
        E::Wire: Into<WireEvidence>,
    {
        let ctx = &prepared.context;
        let nonce: [u8; 16] = rand::random();
        let issued_at = crate::jwt::now_unix()?;
        let operation = StoreSecretOperation {
            encrypted_document_sha256: Sha256::digest(&prepared.encrypted_document).to_vec(),
            enc_cmt: prepared.enc_cmt.clone(),
            ring_id: ring_id.clone(),
            policy_id: ctx.policy_id.clone(),
            resource: ctx.resource.clone(),
            permission: ctx.permission.clone(),
            challenge: prepared.challenge.clone(),
            response: prepared.response.clone(),
            with_proof,
            tier: ctx.tier.clone(),
            timestamp: ctx.timestamp,
            expiry: issued_at + 300,
            nonce,
        };
        let wire: WireEvidence = evidence
            .produce(&operation)
            .map_err(|e| SdkError::Evidence(e.to_string()))?
            .into();

        let mut client = StoreSecretServiceClient::new(self.channel());
        let request = build_request(
            prepared,
            ring_id,
            with_proof,
            pet_tag,
            Some(wire.into_store_secret_assertion()),
        );
        let response = client
            .store_secret(tonic::Request::new(request))
            .await?
            .into_inner();
        Ok(to_result(response))
    }

    /// Encrypts `secret` locally and stores it in one call — a convenience
    /// over [`crate::crypto::prepare_secret`] +
    /// [`OrbisClient::store_prepared_secret_with_jwt`] for a caller that
    /// doesn't need the intermediate [`PreparedSecret`] for retries.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_secret_with_jwt(
        &self,
        secret: &[u8],
        ring_pk_hex: &str,
        ring_id: String,
        policy_id: String,
        resource: String,
        permission: String,
        tier: Option<String>,
        timestamp: Option<u64>,
        salt: Option<String>,
        signer: &impl JwtIdentitySigner,
        derivation: Option<Vec<u8>>,
        with_proof: bool,
    ) -> Result<StoreSecretResult> {
        let prepared = crate::crypto::prepare_secret(
            secret,
            ring_pk_hex,
            derivation,
            policy_id,
            resource,
            permission,
            tier,
            timestamp,
            salt,
            None,
        )?;
        self.store_prepared_secret_with_jwt(&prepared, ring_id, signer, with_proof, None)
            .await
    }
}

fn build_request(
    prepared: &PreparedSecret,
    ring_id: String,
    with_proof: bool,
    pet_tag: Option<&PreparedPetTag>,
    webauthn_assertion: Option<WebAuthnAssertion>,
) -> StoreSecretRequest {
    let ctx = &prepared.context;
    StoreSecretRequest {
        encrypted_document: prepared.encrypted_document.clone(),
        enc_cmt: prepared.enc_cmt.clone(),
        ring_id,
        policy_id: ctx.policy_id.clone(),
        resource: ctx.resource.clone(),
        permission: ctx.permission.clone(),
        challenge: prepared.challenge.clone(),
        response: prepared.response.clone(),
        with_proof,
        tier: ctx.tier.clone(),
        timestamp: ctx.timestamp,
        pet_tag: pet_tag.map(|prepared_tag| PetTagAttachment {
            ephemeral_point: prepared_tag.tag.ephemeral_point.clone(),
            masked_fingerprint: prepared_tag.tag.masked_fingerprint.clone(),
            knowledge_proof_challenge: prepared_tag.tag_proof.challenge.clone(),
            knowledge_proof_response: prepared_tag.tag_proof.response.clone(),
        }),
        webauthn_assertion,
    }
}

fn to_result(response: StoreSecretResponse) -> StoreSecretResult {
    StoreSecretResult {
        status: response.status,
        message: response.message,
        created_at: response.created_at,
        object_id: response.object_id,
        ring_id: response.ring_id,
        signature: response.signature,
    }
}
