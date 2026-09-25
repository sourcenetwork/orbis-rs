//! `start_pre`'s request pipeline, broken into named stages, each returning a small
//! state type that only exposes what later stages need:
//!
//!  1. [`PreServiceImpl::authenticate_pre_request`] (**authentication**) — JWT + claims
//!     + reader-key proof-of-possession. No IO.
//!  2. [`PreServiceImpl::resolve_pre_bulletin_state`] (**bulletin reads**) — resolves the
//!     document/ring payloads live from the bulletin.
//!  3. [`PreServiceImpl::authorize_pre_request`] (**policy checks**) — on-chain ACP
//!     check, then single-use JWT enforcement, then Schnorr ciphertext-binding
//!     verification.
//!  4. [`PreServiceImpl::check_pet_if_required`] (**PET check**) — a no-op unless
//!     the ring requires PET, in which case it runs the threshold ownership-tag
//!     check (see `pet::v0`) and rejects the request on a mismatch.
//!  5. [`PreServiceImpl::prepare_pre_relay`] (**relay setup**) — peer resolution, the
//!     signed relay-forwarding statement, and coordinator input assembly.
//!  6. [`PreServiceImpl::coordinate_pre_reencryption`] (**coordination**) — runs the
//!     threshold re-encryption round.
//!  7. [`encode_pre_response`] (**response encoding**) — turns the coordinator's raw
//!     result into the wire response.
//!
//! Security-sensitive ordering preserved from the original monolithic handler: stage 3
//! enforces single-use JWT consumption strictly *after* the ACP policy check succeeds
//! (see `record_client_jti_after_acp`'s docs) — swapping that order would let a request
//! ACP was going to reject still burn the caller's one-time JWT.
//!
//! `start_pre` itself (the thin orchestrator that calls these in order) lives in
//! `super`, alongside `PreServiceImpl`.

use super::*;
use crate::helpers::auth::{client_valid_window, extract_and_validate_jwt, request_actor};
use crate::helpers::jti_replay::record_client_jti_after_acp;
use crate::helpers::node_routes::resolve_and_validate_peer_ids;
use crate::helpers::ring::RingConfig;
use crate::pre::v0::coordinator::{PreCoordinator, PreReportBinding};
use crate::pre::v0::helpers::{
    build_ciphertext_context, check_policy_access, decode_ring_pk, deserialize_secret,
    resolve_document_and_ring_payloads, validate_pre_claims, verify_encryption_binding,
};
use crate::pre::v0::messages::PreRequestContext;
use crate::reporting::v0::types::ReportedDocumentEvidence;
use crate::reporting::v0::{build_signed_relay_statement, RelayStatementInputs};
use crate::ring_state::RingPolyState;
use authn::{BearerToken, PreClaims};
use authz::vera::ValidWindow;
use bulletin::r#trait::{DocumentPayload, RingPayload};
use crypto::context::CiphertextContext;
use crypto::r#trait::ReaderKeyProof;

/// Output of stage 1. The parsed inline document (if any) is returned alongside rather
/// than folded into this type, since only stage 2 consumes it.
pub(super) struct AuthenticatedPreRequest {
    token_str: String,
    pub(super) token: BearerToken<PreClaims>,
    pub(super) object_id: String,
    rdr_pk: Vec<u8>,
    rdr_pk_proof: ReaderKeyProof,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window: Option<ValidWindow>,
    /// The ACP object naming the audit target, required (and only enforced)
    /// on a ring that requires PET — see `check_pet_if_required`.
    audit_target_object_id: Option<String>,
}

/// Output of stage 2: the document and ring state this request resolves to, plus the
/// actor derived from the token and the ring's trusted-relay configuration.
pub(super) struct PreBulletinState {
    document_payload: DocumentPayload,
    ring_payload: RingPayload,
    is_inline: bool,
    document_evidence: Option<ReportedDocumentEvidence>,
    actor_id: String,
}

/// Output of stage 3: a request that has passed authentication, bulletin resolution,
/// on-chain policy authorization, single-use JWT enforcement, and Schnorr
/// ciphertext-binding verification. The remaining stages only set up and run the
/// threshold coordination round.
pub(super) struct AuthorizedPreRequest {
    token_str: String,
    token: BearerToken<PreClaims>,
    object_id: String,
    rdr_pk: Vec<u8>,
    rdr_pk_proof: ReaderKeyProof,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window: Option<ValidWindow>,
    document_payload: DocumentPayload,
    ring_payload: RingPayload,
    is_inline: bool,
    document_evidence: Option<ReportedDocumentEvidence>,
    actor_id: String,
    pub(super) ciphertext_context: CiphertextContext,
    audit_target_object_id: Option<String>,
}

/// Output of stage 4: everything the coordination stage needs to run the threshold
/// round.
pub(super) struct PreRelaySetup {
    request_id: String,
    ring: RingConfig,
    secret_bytes: Vec<u8>,
    ctx: PreRequestContext,
    report_binding: PreReportBinding,
}

/// Rejects an oversized inline document before any JWT or crypto work — mirrors Sign's
/// message-size gate. Redundant with the gRPC transport's
/// `max_decoding_message_size(MAX_PRE_REQUEST_BYTES)` (`runtime.rs`), which already
/// bounds the whole request; this is defense-in-depth so a maximal-but-still-under-that-
/// cap document doesn't spend a JWT signature verification before being rejected.
pub(super) fn validate_pre_request_size(
    request: &Request<StartPreRequest>,
) -> Result<(), PreError> {
    if let Some(document) = request.get_ref().document.as_ref() {
        if document.encrypted_document.len() > crate::constants::MAX_PRE_REQUEST_BYTES {
            return Err(PreError::InvalidInput(format!(
                "Inline document too large: {} bytes exceeds maximum {}",
                document.encrypted_document.len(),
                crate::constants::MAX_PRE_REQUEST_BYTES
            )));
        }
    }
    Ok(())
}

/// Response-encoding stage (6): parses the coordinator's raw result and attaches the
/// verified ciphertext-binding context so the reader can rebuild the AAD.
pub(super) fn encode_pre_response(
    result: Vec<u8>,
    ciphertext_context: CiphertextContext,
    created_at: i64,
) -> Result<StartPreResponse, PreError> {
    let pre_response: crate::pre::v0::coordinator::PreResponse = serde_json::from_slice(&result)
        .map_err(|e| PreError::Deserialization(format!("Failed to parse PRE result: {}", e)))?;
    let wire_response = crate::pre::v0::coordinator::PreReencryptResponse {
        xnc_cmt: pre_response.xnc_cmt,
        secret: pre_response.secret,
        context: ciphertext_context,
    };

    let encrypted_secret = serde_json::to_vec(&wire_response)
        .map_err(|e| PreError::Serialization(format!("Failed to serialize response: {}", e)))?;

    Ok(StartPreResponse {
        status: "completed".to_string(),
        message: "PRE completed successfully".to_string(),
        created_at,
        encrypted_secret,
    })
}

impl<D, T> PreServiceImpl<D, T>
where
    D: Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
            PubPoly = crypto::PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
    T: ThresholdDealer<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = DistKeyShare<crypto::ScalarField>,
            Secret = Secret,
            ReencryptReply = ReencryptReply<crypto::ScalarField, crypto::GroupAffine>,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
{
    /// Stage 1 (authentication): extracts and validates the JWT, checks its claims
    /// against the request, and verifies the reader's proof of knowledge of `rdr_pk`'s
    /// discrete log.
    ///
    /// The reader-key proof is re-verified independently by every committee member
    /// inside `ThresholdDealer::reencrypt` (the actual security boundary — see
    /// `ReaderKeyProof`'s docs); checking it here too just fails fast, before a
    /// threshold round trip, on a missing or malformed proof.
    pub(super) fn authenticate_pre_request(
        request: Request<StartPreRequest>,
        current_time: u64,
    ) -> Result<(AuthenticatedPreRequest, Option<DocumentPayload>), PreError> {
        let (token_str, token) = extract_and_validate_jwt::<PreClaims, _>(&request, current_time)
            .map_err(PreError::Unauthorized)?;

        let mut req = request.into_inner();

        let valid_window = client_valid_window(req.valid_window.map(|w| (w.start, w.end)));

        validate_pre_claims(
            &token,
            &req.rdr_pk,
            &req.object_id,
            &req.derivation,
            &req.salt,
        )?;

        let rdr_pk_proof = req
            .rdr_pk_proof
            .take()
            .map(|p| ReaderKeyProof {
                challenge: p.challenge,
                response: p.response,
            })
            .ok_or_else(|| PreError::InvalidInput("Missing rdr_pk_proof".to_string()))?;
        let rdr_pk_point = <T::PublicKey as crypto::r#trait::CryptoDeserialize>::from_bytes(
            &req.rdr_pk,
        )
        .map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;
        T::verify_reader_key(&rdr_pk_point, &rdr_pk_proof)
            .map_err(|e| PreError::Unauthorized(format!("Invalid reader key proof: {}", e)))?;

        let inline_document = req
            .document
            .take()
            .map(document_payload_from_inline)
            .transpose()?;

        Ok((
            AuthenticatedPreRequest {
                token_str,
                token,
                object_id: req.object_id,
                rdr_pk: req.rdr_pk,
                rdr_pk_proof,
                derivation: req.derivation,
                salt: req.salt,
                valid_window,
                audit_target_object_id: req.audit_target_object_id,
            },
            inline_document,
        ))
    }

    /// Stage 2 (bulletin reads): resolves the document (from the caller-supplied inline
    /// payload or, when absent, from the bulletin by `object_id`) and the ring's live
    /// payload, then derives the acting identity from the token and the ring's
    /// trusted-relay configuration.
    pub(super) async fn resolve_pre_bulletin_state(
        &self,
        object_id: &str,
        inline_document: Option<DocumentPayload>,
        token: &BearerToken<PreClaims>,
    ) -> Result<PreBulletinState, PreError> {
        let is_inline = inline_document.is_some();
        let (document_payload, ring_payload) = resolve_document_and_ring_payloads(
            &*self.state.bulletin,
            object_id,
            self.routes.version,
            inline_document,
        )
        .await?;
        let document_evidence = is_inline.then(|| ReportedDocumentEvidence {
            document: document_payload.document.clone(),
            proof: document_payload.proof.clone(),
            policy_id: document_payload.policy_id.clone(),
            resource: document_payload.resource.clone(),
            permission: document_payload.permission.clone(),
            tier: document_payload.tier.clone(),
        });
        let actor_id = request_actor(token, ring_payload.trusted_auth_relay_dids.as_deref())
            .map_err(PreError::Unauthorized)?;

        Ok(PreBulletinState {
            document_payload,
            ring_payload,
            is_inline,
            document_evidence,
            actor_id,
        })
    }

    /// Stage 3 (policy checks): checks on-chain ACP access, enforces single-use JWT
    /// consumption, and verifies the Schnorr proof binding the ciphertext to the
    /// resolved ring/document/salt context.
    ///
    /// Security-sensitive ordering: `record_client_jti_after_acp` must run *after* the
    /// ACP check succeeds (see that function's docs) — this stage preserves that order
    /// so a caller cannot burn a client's one-time JWT against a request ACP would have
    /// rejected.
    pub(super) async fn authorize_pre_request(
        &self,
        authenticated: AuthenticatedPreRequest,
        bulletin_state: PreBulletinState,
    ) -> Result<AuthorizedPreRequest, PreError> {
        check_policy_access(
            &*self.state.authz,
            &bulletin_state.document_payload,
            &authenticated.object_id,
            &bulletin_state.actor_id,
            authenticated.valid_window.clone(),
        )
        .await?;

        // Single-use JWT enforcement — see `record_client_jti_after_acp`'s docs for why
        // this must come after the ACP check above.
        record_client_jti_after_acp(
            &self.state.jti_guard,
            &authenticated.token.jwt_id,
            authenticated.token.expiration_time,
            "start_pre",
        )
        .await
        .map_err(|e| PreError::Unauthorized(e.to_string()))?;

        let secret = deserialize_secret(&bulletin_state.document_payload.document)?;

        // Rebuild the context the encryptor bound into the proof (ring key + policy
        // fields from the id-checked document + reader-supplied salt) and verify the
        // Schnorr proof against it. A tampered policy field, ring key, nonce, or
        // ciphertext fails here.
        let ciphertext_context = build_ciphertext_context(
            &bulletin_state.ring_payload.ring_pk,
            &bulletin_state.document_payload,
            authenticated.salt.as_deref(),
        )?;
        verify_encryption_binding(
            &ciphertext_context,
            &secret,
            bulletin_state.document_payload.proof.clone(),
        )?;

        tracing::info!(
            ring_id = %bulletin_state.document_payload.ring_id,
            ring_pk = %bulletin_state.ring_payload.ring_pk,
            reader_pk = ?authenticated.rdr_pk,
            peer_node_keys = ?bulletin_state.ring_payload.peer_node_keys,
            issuer = %authenticated.token.issuer_id,
            actor = %bulletin_state.actor_id,
            "Authenticated StartPre request"
        );

        Ok(AuthorizedPreRequest {
            token_str: authenticated.token_str,
            token: authenticated.token,
            object_id: authenticated.object_id,
            rdr_pk: authenticated.rdr_pk,
            rdr_pk_proof: authenticated.rdr_pk_proof,
            derivation: authenticated.derivation,
            salt: authenticated.salt,
            valid_window: authenticated.valid_window,
            document_payload: bulletin_state.document_payload,
            ring_payload: bulletin_state.ring_payload,
            is_inline: bulletin_state.is_inline,
            document_evidence: bulletin_state.document_evidence,
            actor_id: bulletin_state.actor_id,
            ciphertext_context,
            audit_target_object_id: authenticated.audit_target_object_id,
        })
    }

    /// Stage 4 (PET check): when the ring requires PET, runs the threshold
    /// ownership-tag check and rejects the request unless it matches the
    /// authenticated audit target. A no-op (returning no attestations) for a
    /// ring that doesn't require PET — `audit_target_object_id` is only ever
    /// required in that case.
    ///
    /// Placed after `authorize_pre_request` (ACP access to the document
    /// itself must already have passed) and before `prepare_pre_relay` (no
    /// point resolving peers/building the relay statement for a request that
    /// fails the ownership check).
    ///
    /// The returned attestations are forwarded by `prepare_pre_relay` into
    /// every `ReencryptRequest` so each PRE peer can independently verify
    /// this same check before releasing its share, instead of trusting this
    /// node's pass/fail result alone — see
    /// `pet::v0::coordinator::verification::verify_pet_admission`'s doc
    /// comment for why that closes a real gap: without it, nothing on the
    /// peer side ever consulted `requires_pet` at all.
    pub(super) async fn check_pet_if_required(
        &self,
        authorized: &AuthorizedPreRequest,
    ) -> Result<Vec<crate::pet::v0::attestation::PetShareAttestation>, PreError> {
        if !authorized.ring_payload.requires_pet {
            return Ok(Vec::new());
        }
        let audit_target_object_id =
            authorized.audit_target_object_id.clone().ok_or_else(|| {
                PreError::InvalidInput(
                    "ring requires PET but no audit_target_object_id was supplied".to_string(),
                )
            })?;

        let coordinator =
            crate::pet::v0::coordinator::PetCoordinator::<D, crypto::PetImpl>::with_routes(
                self.state.clone(),
                self.routes,
            );
        let request_id = rand::random::<u64>().to_string();
        coordinator
            .initiate_pet_check(
                request_id,
                authorized.document_payload.clone(),
                authorized.salt.clone(),
                audit_target_object_id,
            )
            .await
            .map_err(PreError::from)
    }

    /// Stage 5 (relay setup): resolves and validates the ring's peers, builds this
    /// node's signed relay-forwarding statement (so a peer whose own ACP re-check fails
    /// can attribute the request back to this relay), and assembles the ring/request
    /// context the coordination stage hands to `PreCoordinator`.
    pub(super) async fn prepare_pre_relay(
        &self,
        authorized: AuthorizedPreRequest,
        pet_attestations: Vec<crate::pet::v0::attestation::PetShareAttestation>,
    ) -> Result<PreRelaySetup, PreError> {
        let secret_bytes = authorized.document_payload.document.as_bytes().to_vec();

        let peer_ids = resolve_and_validate_peer_ids(
            &self.state.bulletin,
            &authorized.ring_payload.peer_node_keys,
            "No peer node keys provided for reencryption",
        )
        .await
        .map_err(PreError::InvalidInput)?;

        let request_id = rand::random::<u64>().to_string();
        let total_participants = peer_ids.len();

        let (ring_pk_bytes, ring_pk) = decode_ring_pk(&authorized.ring_payload.ring_pk)?;
        let poly_state = RingPolyState::load(&self.state.local_storage, &ring_pk).map_err(|e| {
            tracing::error!("Failed to load ring polynomial state: {}", e);
            PreError::RingState("Failed to load ring polynomial state".to_string())
        })?;

        // Chain/ring binding for invalid-proof reporting, taken from the same payloads
        // that authorized this request (must be built before
        // `ring_payload.peer_node_keys` is moved into the RingConfig below).
        let report_binding = PreReportBinding::from_ring(
            self.state.bulletin.chain_id(),
            authorized.document_payload.ring_id.clone(),
            &authorized.ring_payload,
            authorized.document_payload.timestamp,
            authorized.document_evidence,
        );

        // The relayer signs a record that it forwarded this request (after passing its
        // own ACP check above), so a peer whose re-check fails can attribute it via
        // `unauthorized_request`. `document_inline` (set when this request's document
        // was supplied inline) tells the report verifier to expect the document
        // out-of-band rather than read it from the bulletin; the ciphertext itself is
        // never signed into the statement.
        let (relay_statement, relay_signature) = build_signed_relay_statement(
            RelayStatementInputs {
                ring: authorized.ring_payload.clone(),
                ring_id: authorized.document_payload.ring_id.clone(),
                protocol_version: self.routes.version,
                chain_id: self.state.bulletin.chain_id(),
                request_id: request_id.clone(),
                origin_protocol: "pre".to_string(),
                relayer_node_key: self.state.node_key.clone(),
                actor_id: authorized.actor_id,
                object_id: authorized.object_id.clone(),
                user_signed_at: authorized.token.issued_time,
                acp_timestamp: authorized.document_payload.timestamp,
                valid_window: authorized.valid_window.clone(),
                document_inline: authorized.is_inline,
            },
            &self.state.local_storage,
        )
        .map_err(|e| PreError::Generic(format!("Failed to build relay statement: {}", e)))?;

        let ctx_document = authorized
            .is_inline
            .then(|| authorized.document_payload.clone());

        let ring = RingConfig {
            ring_id: authorized.document_payload.ring_id.clone(),
            ring_pk_bytes,
            peer_ids,
            peer_node_keys: authorized.ring_payload.peer_node_keys,
            threshold: authorized.ring_payload.threshold as usize,
            total_participants,
            public_polynomial_hex: poly_state.public_polynomial,
        };
        let ctx = PreRequestContext {
            rdr_pk_bytes: authorized.rdr_pk,
            rdr_pk_proof: authorized.rdr_pk_proof,
            object_id: authorized.object_id,
            token_string: authorized.token_str,
            derivation: authorized.derivation,
            salt: authorized.salt,
            valid_window: authorized.valid_window,
            relay_statement: Some(relay_statement),
            relay_signature,
            document: ctx_document,
            audit_target_object_id: authorized.audit_target_object_id,
            pet_attestations,
        };

        Ok(PreRelaySetup {
            request_id,
            ring,
            secret_bytes,
            ctx,
            report_binding,
        })
    }

    /// Stage 6 (coordination): runs the threshold re-encryption round across the ring's
    /// peers.
    pub(super) async fn coordinate_pre_reencryption(
        &self,
        setup: PreRelaySetup,
    ) -> Result<Vec<u8>, PreError> {
        let coordinator = PreCoordinator::<D, T>::with_routes(self.state.clone(), self.routes);
        coordinator
            .initiate_reencryption(
                setup.request_id,
                setup.ring,
                setup.secret_bytes,
                setup.ctx,
                setup.report_binding,
            )
            .await
    }
}
