//! Test-only PET protocol decorator. It delegates validation to the real
//! coordinator before altering a successful, signed decrypt reply.

use crate::helpers::protocol_handler::MessageCoordinator;
use crate::pet::v0::{coordinator::PetCoordinator, error::PetError, messages::PetMessage};
use crate::reporting::v0::types::{
    PetBlindDecryptStatement, PetBlindRevealStatement, PET_BLIND_DECRYPT_RESPONSE_DOMAIN,
};
use async_trait::async_trait;
use common::blockchain::{sign_node_message_with_hex_key, verify_node_message, BlockchainError};
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize};
use crypto::{DkgImpl, PetImpl, ScalarField};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::PeerId;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Default)]
pub(crate) struct PetFaultControl {
    ring_id: Mutex<Option<String>>,
}

impl PetFaultControl {
    pub(crate) async fn set(&self, ring_id: String, enabled: bool) {
        let mut target = self.ring_id.lock().await;
        if enabled {
            *target = Some(ring_id);
        } else if target.as_deref() == Some(ring_id.as_str()) {
            *target = None;
        }
    }

    async fn enabled_for(&self, ring_id: &str) -> bool {
        self.ring_id.lock().await.as_deref() == Some(ring_id)
    }
}

#[derive(Debug, Error)]
pub(crate) enum PetFaultError {
    #[error(transparent)]
    Coordinator(#[from] PetError),
    #[error("testing PET response has no validated certificate binding")]
    MissingBinding,
    #[error("testing PET proof codec failed")]
    Codec(#[from] crypto::error::CryptoError),
    #[error("testing PET node signature failed")]
    Signature(#[from] BlockchainError),
    #[error("testing PET signing key read failed")]
    Storage(#[from] local_storage::error::LocalStorageError),
    #[error("testing PET signing key is missing")]
    MissingSigningKey,
    #[error("testing PET signing key is not UTF-8")]
    SigningKeyEncoding(#[from] std::str::Utf8Error),
}

// Captured from the request's certificate, then authenticated against the real
// coordinator's response signature. No second bulletin read can race a reshare.
struct Binding {
    chain_id: String,
    ring_id: String,
    ring_pk: String,
    ring_state_sha256: String,
    protocol_version: u64,
}

impl From<&PetBlindRevealStatement> for Binding {
    fn from(statement: &PetBlindRevealStatement) -> Self {
        Self {
            chain_id: statement.chain_id.clone(),
            ring_id: statement.ring_id.clone(),
            ring_pk: statement.ring_pk.clone(),
            ring_state_sha256: statement.ring_state_sha256.clone(),
            protocol_version: statement.protocol_version,
        }
    }
}

pub(crate) struct PetFaultCoordinator {
    inner: PetCoordinator<DkgImpl, PetImpl>,
    control: Arc<PetFaultControl>,
}

impl PetFaultCoordinator {
    pub(crate) fn new(
        inner: PetCoordinator<DkgImpl, PetImpl>,
        control: Arc<PetFaultControl>,
    ) -> Self {
        Self { inner, control }
    }

    pub(crate) async fn handle_message(
        &self,
        message: PetMessage,
        peer_id: &PeerId,
    ) -> Result<Option<PetMessage>, PetFaultError> {
        let binding = match &message {
            PetMessage::DecryptRequest(request) => request
                .certificate
                .reveals
                .first()
                .map(|reveal| Binding::from(&reveal.statement)),
            _ => None,
        };
        let mut response = self.inner.handle_message(message, peer_id).await?;
        let Some(PetMessage::DecryptResponse {
            attempt_id,
            context_digest,
            certificate_digest,
            from_node_id,
            aggregate_r,
            aggregate_diff,
            partial,
            challenge,
            proof,
            signed_at,
            public_polynomial,
            response_signature,
            ..
        }) = response.as_mut()
        else {
            // In particular, GenerationMismatch and rejected requests cannot
            // become signed crypto faults, and other protocol phases delegate.
            return Ok(response);
        };
        let binding = binding.ok_or(PetFaultError::MissingBinding)?;
        if !self.control.enabled_for(&binding.ring_id).await {
            return Ok(response);
        }
        let mut statement = PetBlindDecryptStatement {
            domain: PET_BLIND_DECRYPT_RESPONSE_DOMAIN.into(),
            chain_id: binding.chain_id,
            ring_id: binding.ring_id,
            ring_pk: binding.ring_pk,
            ring_state_sha256: binding.ring_state_sha256,
            protocol_version: binding.protocol_version,
            attempt_id: attempt_id.clone(),
            context_digest: *context_digest,
            certificate_digest: *certificate_digest,
            responder_node_key: self.inner.app_state.node_key.clone(),
            from_node_id: *from_node_id,
            aggregate_r: aggregate_r.clone(),
            aggregate_diff: aggregate_diff.clone(),
            partial: partial.clone(),
            challenge: challenge.clone(),
            proof: proof.clone(),
            signed_at: *signed_at,
            public_polynomial: public_polynomial.clone(),
        };
        verify_node_message(
            &statement.responder_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )?;
        statement.proof = (ScalarField::from_bytes(proof)? + ScalarField::from(1u64)).to_bytes()?;
        let key = self
            .inner
            .app_state
            .local_storage
            .get_encrypted(LocalStorageKeys::NodeSigningKey)?
            .ok_or(PetFaultError::MissingSigningKey)?;
        let signature = sign_node_message_with_hex_key(
            std::str::from_utf8(&key)?,
            &statement.canonical_bytes(),
        )?;
        *proof = statement.proof;
        *response_signature = signature;
        Ok(response)
    }
}

#[async_trait]
impl MessageCoordinator for PetFaultCoordinator {
    type Msg = PetMessage;

    fn protocol_name(&self) -> &'static str {
        self.inner.protocol_name()
    }

    fn message_id(message: &PetMessage) -> String {
        PetCoordinator::<DkgImpl, PetImpl>::message_id(message)
    }

    fn make_error(&self, id: &str, error: String) -> PetMessage {
        self.inner.make_error(id, error)
    }

    async fn try_store_response(&self, message: PetMessage, peer: &PeerId) -> Option<PetMessage> {
        self.inner.try_store_response(message, peer).await
    }

    async fn route_message(
        &self,
        message: PetMessage,
        peer: &PeerId,
    ) -> anyhow::Result<Option<PetMessage>> {
        self.handle_message(message, peer).await.map_err(Into::into)
    }
}
