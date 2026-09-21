//! `start_sign`'s request pipeline, broken into named stages, each returning a small
//! state type that only exposes what later stages need (mirrors PRE's `start_pre`
//! pipeline — see `pre::v0::service::stages`'s module docs):
//!
//!  1. [`authenticate_sign_request`] (**authentication**) — JWT + claims. No IO.
//!  2. [`SignServiceImpl::resolve_sign_bulletin_state`] (**bulletin reads**) — resolves
//!     the key-derivation/ring payloads live from the bulletin.
//!  3. [`SignServiceImpl::authorize_sign_request`] (**policy checks**) — on-chain ACP
//!     check, then single-use JWT enforcement.
//!  4. [`SignServiceImpl::prepare_sign_relay`] (**relay setup**) — peer resolution, the
//!     signed relay-forwarding statement, and coordinator input assembly.
//!  5. [`SignServiceImpl::coordinate_sign`] (**coordination**) — runs the threshold
//!     signing round.
//!  6. [`encode_sign_response`] (**response encoding**) — turns the coordinator's raw
//!     result into the wire response.
//!
//! Security-sensitive ordering preserved from the original monolithic handler: stage 3
//! enforces single-use JWT consumption strictly *after* the ACP policy check succeeds
//! (see `record_client_jti_after_acp`'s docs) — swapping that order would let a request
//! ACP was going to reject still burn the caller's one-time JWT.
//!
//! `start_sign` itself (the thin orchestrator that calls these in order) lives in
//! `super`, alongside `SignServiceImpl`.

use super::*;
use crate::helpers::auth::{client_valid_window, extract_and_validate_jwt, request_actor};
use crate::helpers::jti_replay::record_client_jti_after_acp;
use crate::helpers::node_routes::resolve_and_validate_peer_ids;
use crate::helpers::ring::RingConfig;
use crate::reporting::v0::{build_signed_relay_statement, RelayStatementInputs};
use crate::ring_state::RingPolyState;
use crate::sign::v0::coordinator::{SignCoordinator, SigningOptions};
use crate::sign::v0::helpers::{
    check_policy_access_at, fetch_bulletin_payloads_for_version, policy_access_timestamp,
    validate_sign_claims,
};
use crate::sign::v0::messages::{PolicyContext, SignContext};
use authn::{BearerToken, SignClaims};
use authz::vera::ValidWindow;
use bulletin::r#trait::{KeyDerivation, RingPayload};

/// Output of stage 1.
pub(super) struct AuthenticatedSignRequest {
    token_string: String,
    pub(super) token: BearerToken<SignClaims>,
    pub(super) derivation_id: String,
    message: Vec<u8>,
    valid_window: Option<ValidWindow>,
}

/// Output of stage 2: the key-derivation and ring state this request resolves to, plus
/// the actor derived from the token and the ring's trusted-relay configuration.
pub(super) struct SignBulletinState {
    key_derivation: KeyDerivation,
    ring_payload: RingPayload,
    actor_id: String,
}

/// Output of stage 3: a request that has passed authentication, bulletin resolution,
/// on-chain policy authorization, and single-use JWT enforcement. The remaining stages
/// only set up and run the threshold coordination round.
pub(super) struct AuthorizedSignRequest {
    token_string: String,
    token: BearerToken<SignClaims>,
    derivation_id: String,
    message: Vec<u8>,
    valid_window: Option<ValidWindow>,
    key_derivation: KeyDerivation,
    ring_payload: RingPayload,
    actor_id: String,
    relay_acp_timestamp: Option<u64>,
}

/// Output of stage 4: everything the coordination stage needs to run the threshold
/// round.
pub(super) struct SignRelaySetup {
    request_id: String,
    ring: RingConfig,
    message: Vec<u8>,
    context: SignContext,
}

/// Rejects an oversized message before any crypto work.
pub(super) fn validate_sign_message_size(
    request: &Request<StartSignRequest>,
) -> Result<(), SignError> {
    if request.get_ref().message.len() > crate::constants::MAX_SIGN_MESSAGE_BYTES {
        return Err(SignError::InvalidInput(format!(
            "Message too large: {} bytes exceeds maximum {}",
            request.get_ref().message.len(),
            crate::constants::MAX_SIGN_MESSAGE_BYTES
        )));
    }
    Ok(())
}

/// Stage 1 (authentication): extracts and validates the JWT and checks its claims
/// against the request. No IO.
pub(super) fn authenticate_sign_request(
    request: Request<StartSignRequest>,
    current_time: u64,
) -> Result<AuthenticatedSignRequest, SignError> {
    let (token_string, token) = extract_and_validate_jwt::<SignClaims, _>(&request, current_time)
        .map_err(SignError::Unauthorized)?;

    let req = request.into_inner();

    validate_sign_claims(&token, &req.derivation_id, Some(&req.message))?;

    let valid_window = client_valid_window(req.valid_window.map(|w| (w.start, w.end)));

    Ok(AuthenticatedSignRequest {
        token_string,
        token,
        derivation_id: req.derivation_id,
        message: req.message,
        valid_window,
    })
}

/// Response-encoding stage (6): parses the coordinator's raw result into the wire
/// response.
pub(super) fn encode_sign_response(
    result: Vec<u8>,
    created_at: i64,
) -> Result<StartSignResponse, SignError> {
    let sign_response: crate::sign::v0::coordinator::SignResponse = serde_json::from_slice(&result)
        .map_err(|e| SignError::Deserialization(format!("Failed to parse sign result: {}", e)))?;

    Ok(StartSignResponse {
        status: "completed".to_string(),
        message: "Sign completed successfully".to_string(),
        created_at,
        signature: sign_response.signature,
    })
}

impl<D, S> SignServiceImpl<D, S>
where
    D: Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    S: ThresholdSigner<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = DistKeyShare<crypto::ScalarField>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    /// Stage 2 (bulletin reads): resolves the key-derivation and ring payloads live
    /// from the bulletin, then derives the acting identity from the token and the
    /// ring's trusted-relay configuration.
    pub(super) async fn resolve_sign_bulletin_state(
        &self,
        derivation_id: &str,
        token: &BearerToken<SignClaims>,
    ) -> Result<SignBulletinState, SignError> {
        let (key_derivation, ring_payload) = fetch_bulletin_payloads_for_version(
            &*self.state.bulletin,
            derivation_id,
            true,
            self.routes.version,
        )
        .await?;
        let actor_id = request_actor(token, ring_payload.trusted_auth_relay_dids.as_deref())
            .map_err(SignError::Unauthorized)?;

        Ok(SignBulletinState {
            key_derivation,
            ring_payload,
            actor_id,
        })
    }

    /// Stage 3 (policy checks): checks on-chain ACP access at a timestamp pinned before
    /// the check began, then enforces single-use JWT consumption.
    ///
    /// Security-sensitive ordering: `record_client_jti_after_acp` must run *after* the
    /// ACP check succeeds (see that function's docs) — this stage preserves that order
    /// so a caller cannot burn a client's one-time JWT against a request ACP would have
    /// rejected.
    pub(super) async fn authorize_sign_request(
        &self,
        authenticated: AuthenticatedSignRequest,
        bulletin_state: SignBulletinState,
    ) -> Result<AuthorizedSignRequest, SignError> {
        // Sign's ACP check only stamps a timestamp when a valid window is present. The
        // exact timestamp is reused for the relay statement in the next stage so it
        // cannot drift across a window boundary while JWT/bulletin IO is in flight.
        let relay_acp_timestamp = policy_access_timestamp(authenticated.valid_window.as_ref())?;
        check_policy_access_at(
            &*self.state.authz,
            &bulletin_state.key_derivation,
            &authenticated.derivation_id,
            &bulletin_state.actor_id,
            authenticated.valid_window.clone(),
            relay_acp_timestamp,
        )
        .await?;

        // Single-use JWT enforcement — see `record_client_jti_after_acp`'s docs for why
        // this must come after the ACP check above.
        record_client_jti_after_acp(
            &self.state.jti_guard,
            &authenticated.token.jwt_id,
            authenticated.token.expiration_time,
            "start_sign",
        )
        .await
        .map_err(|e| SignError::Unauthorized(e.to_string()))?;

        tracing::info!(
            derivation_id = %authenticated.derivation_id,
            ring_id = %bulletin_state.key_derivation.ring_id,
            ring_pk = %bulletin_state.ring_payload.ring_pk,
            peer_node_keys = ?bulletin_state.ring_payload.peer_node_keys,
            issuer = %authenticated.token.issuer_id,
            actor = %bulletin_state.actor_id,
            "Authenticated StartSign request"
        );

        Ok(AuthorizedSignRequest {
            token_string: authenticated.token_string,
            token: authenticated.token,
            derivation_id: authenticated.derivation_id,
            message: authenticated.message,
            valid_window: authenticated.valid_window,
            key_derivation: bulletin_state.key_derivation,
            ring_payload: bulletin_state.ring_payload,
            actor_id: bulletin_state.actor_id,
            relay_acp_timestamp,
        })
    }

    /// Stage 4 (relay setup): resolves and validates the ring's peers, builds this
    /// node's signed relay-forwarding statement (so a peer whose own ACP re-check fails
    /// can attribute the request back to this relay), and assembles the ring/policy
    /// context the coordination stage hands to `SignCoordinator`.
    pub(super) async fn prepare_sign_relay(
        &self,
        authorized: AuthorizedSignRequest,
    ) -> Result<SignRelaySetup, SignError> {
        let peer_ids = resolve_and_validate_peer_ids(
            &self.state.bulletin,
            &authorized.ring_payload.peer_node_keys,
            "No peer node keys found for ring",
        )
        .await
        .map_err(SignError::InvalidInput)?;

        let ring_pk_bytes = hex::decode(&authorized.ring_payload.ring_pk).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", e))
        })?;

        let request_id = rand::random::<u64>().to_string();
        let total_participants = peer_ids.len();
        let poly_state = RingPolyState::load_from_ring_pk_hex(
            &self.state.local_storage,
            &authorized.ring_payload.ring_pk,
        )
        .map_err(|e| {
            SignError::RingState(format!("Failed to load ring polynomial state: {}", e))
        })?;

        // The relayer signs a record that it forwarded this request (after passing its
        // own ACP check above), so a peer whose re-check fails can attribute it via
        // `unauthorized_request`. `relay_acp_timestamp` is the exact timestamp taken
        // during authorization, reused here so it cannot drift across a window
        // boundary.
        let (relay_statement, relay_signature) = build_signed_relay_statement(
            RelayStatementInputs {
                ring: authorized.ring_payload.clone(),
                ring_id: authorized.key_derivation.ring_id.clone(),
                protocol_version: self.routes.version,
                chain_id: self.state.bulletin.chain_id(),
                request_id: request_id.clone(),
                origin_protocol: "sign".to_string(),
                relayer_node_key: self.state.node_key.clone(),
                actor_id: authorized.actor_id,
                object_id: authorized.derivation_id.clone(),
                user_signed_at: authorized.token.issued_time,
                acp_timestamp: authorized.relay_acp_timestamp,
                valid_window: authorized.valid_window.clone(),
                document_inline: false,
            },
            &self.state.local_storage,
        )
        .map_err(|e| SignError::Generic(format!("Failed to build relay statement: {}", e)))?;

        let ring = RingConfig {
            ring_id: authorized.key_derivation.ring_id.clone(),
            ring_pk_bytes,
            peer_ids,
            peer_node_keys: authorized.ring_payload.peer_node_keys,
            threshold: authorized.ring_payload.threshold as usize,
            total_participants,
            public_polynomial_hex: poly_state.public_polynomial,
        };

        let context = SignContext::Policy(Box::new(PolicyContext {
            token_string: authorized.token_string,
            derivation_id: authorized.derivation_id,
            valid_window: authorized.valid_window,
            key_derivation: authorized.key_derivation,
            relay_statement: Some(relay_statement),
            relay_signature,
        }));

        Ok(SignRelaySetup {
            request_id,
            ring,
            message: authorized.message,
            context,
        })
    }

    /// Stage 5 (coordination): runs the threshold signing round across the ring's
    /// peers.
    pub(super) async fn coordinate_sign(
        &self,
        setup: SignRelaySetup,
    ) -> Result<Vec<u8>, SignError> {
        let coordinator = SignCoordinator::<D, S>::with_routes(self.state.clone(), self.routes);
        coordinator
            .initiate_signing(
                setup.request_id,
                setup.ring,
                setup.message,
                setup.context,
                SigningOptions::default(),
            )
            .await
    }
}
