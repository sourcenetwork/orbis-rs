//! Passkey signing reference application.
//!
//! Serves a small browser UI (`web/`) that registers a passkey and uses it
//! to authorize a threshold Sign request — no password, no JWT, no
//! separate enrollment step: the passkey's own public key *is* the
//! identity ACP grants or revokes directly (see `orbis-webauthn`'s and
//! `orbis-integration-core`'s doc comments for why).
//!
//! This process is a thin bridge, nothing more: browsers can't speak gRPC
//! directly, so it turns the browser's WebAuthn output into evidence for
//! `orbis-sdk`'s own Sign/PRE requests. It never verifies anything
//! itself — every ring node does that independently; a verification
//! result produced here would not be proof for anyone else.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use orbis_sdk::{OrbisClient, PendingPre, PendingSign, SdkError};
use orbis_webauthn::RawAssertion;
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Parser, Debug, Clone)]
#[command(name = "passkey-sign")]
#[command(about = "Passkey signing reference application")]
struct Args {
    /// Address this server binds to.
    #[arg(long, default_value = "127.0.0.1:8787")]
    addr: String,
    /// orbis-node gRPC endpoint to forward Sign/PRE requests to.
    #[arg(long, env = "ORBIS_ENDPOINT", default_value = "http://127.0.0.1:50051")]
    orbis_endpoint: String,
    /// Relying-party ID to embed in WebAuthn ceremonies — must match the
    /// orbis-node cluster's own `--webauthn-rp-id`.
    #[arg(long, env = "ORBIS_WEBAUTHN_RP_ID", default_value = "localhost")]
    rp_id: String,
    /// Origin to embed in WebAuthn ceremonies — must match the orbis-node
    /// cluster's own `--webauthn-origin`.
    #[arg(
        long,
        env = "ORBIS_WEBAUTHN_ORIGIN",
        default_value = "http://localhost:8787"
    )]
    origin: String,
    /// Chain id the ring's PRE reader-key proof-of-possession transcript
    /// binds to — must match the ring's own chain.
    #[arg(long, env = "ORBIS_CHAIN_ID")]
    chain_id: String,
}

struct AppState {
    orbis_endpoint: String,
    rp_id: String,
    origin: String,
    chain_id: String,
    /// Sign's challenge and PRE's reader keypair + reader-authorization
    /// transcript both have to be decided *before* the WebAuthn challenge
    /// can be built, but the request can't be submitted until *after* the
    /// browser's ceremony produces an assertion — so, unlike `/api/register`,
    /// these two flows need to hold state across their own two calls. Plain
    /// in-memory maps, not persisted or swept: fine for a single-process
    /// reference app, not a production pattern.
    pending_sign: std::sync::Mutex<std::collections::HashMap<String, PendingSign>>,
    pending_pre: std::sync::Mutex<std::collections::HashMap<String, PendingPre>>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let addr = args.addr.clone();
    let origin = args.origin.clone();
    let state = Arc::new(AppState {
        orbis_endpoint: args.orbis_endpoint,
        rp_id: args.rp_id,
        origin: args.origin,
        chain_id: args.chain_id,
        pending_sign: std::sync::Mutex::new(std::collections::HashMap::new()),
        pending_pre: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/api/config", get(config))
        .route("/api/register", post(register))
        .route("/api/challenge", post(challenge))
        .route("/api/sign", post(sign))
        .route("/api/pre/challenge", post(pre_challenge))
        .route("/api/pre/decrypt", post(pre_decrypt))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind HTTP listener");
    println!("passkey-sign reference app listening on {addr}");
    println!(
        "Open {origin} in your browser — WebAuthn requires the page's actual \
         origin to match --origin/--rp-id exactly, so a different host/port \
         (e.g. the bind address above, if it differs) will fail registration \
         with a SecurityError."
    );
    axum::serve(listener, app).await.expect("serve");
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn app_js() -> Response {
    (
        [("content-type", "application/javascript")],
        include_str!("../web/app.js"),
    )
        .into_response()
}

#[derive(Serialize)]
struct ConfigResponse {
    rp_id: String,
    origin: String,
}

async fn config(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        rp_id: state.rp_id.clone(),
        origin: state.origin.clone(),
    })
}

/// Base64 (standard, padded) SPKI DER public key from
/// `AuthenticatorAttestationResponse.getPublicKey()`. Registration needs no
/// stored challenge or attestation check here: this app never verifies
/// anything, and the identity is just a pure function of the public key.
#[derive(Deserialize)]
struct RegisterRequest {
    public_key_spki_b64: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    did: String,
}

async fn register(Json(req): Json<RegisterRequest>) -> Result<Json<RegisterResponse>, ApiError> {
    let spki = decode_standard_b64(&req.public_key_spki_b64)
        .map_err(|e| ApiError::bad_request(format!("invalid base64: {e}")))?;
    let verifying_key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki)
        .map_err(|e| ApiError::bad_request(format!("invalid P-256 SPKI public key: {e}")))?;
    let compressed: [u8; 33] = verifying_key
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::internal("compressed P-256 point is not 33 bytes"))?;
    Ok(Json(RegisterResponse {
        did: authn::did_from_p256_public_key(&compressed),
    }))
}

#[derive(Deserialize)]
struct ChallengeRequest {
    derivation_id: String,
    message_hex: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    request_token: String,
    challenge_b64url: String,
}

/// Builds a Sign challenge via `orbis_sdk::build_sign_challenge` and holds
/// it, keyed by a fresh `request_token`, until `/api/sign` consumes it —
/// the same request_token/pending-map pattern `/api/pre/challenge` already
/// uses, since both need to hold ephemeral state across the browser's own
/// WebAuthn ceremony.
async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let message = hex::decode(&req.message_hex)
        .map_err(|e| ApiError::bad_request(format!("invalid message hex: {e}")))?;

    let pending = orbis_sdk::build_sign_challenge(req.derivation_id, message, None, None)
        .map_err(ApiError::from_sdk_error)?;
    let challenge_b64url = encode_challenge(&pending.challenge());
    let request_token = hex::encode(rand::random::<[u8; 16]>());
    state
        .pending_sign
        .lock()
        .expect("pending_sign mutex poisoned")
        .insert(request_token.clone(), pending);

    Ok(Json(ChallengeResponse {
        request_token,
        challenge_b64url,
    }))
}

#[derive(Deserialize)]
struct SignRequest {
    request_token: String,
    issuer_did: String,
    authenticator_data_b64: String,
    client_data_json_b64: String,
    signature_b64: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature_hex: String,
}

/// Finishes a passkey-authorized Sign request given the pending challenge
/// `/api/challenge` stashed and the WebAuthn assertion a ceremony against
/// it produced.
async fn sign(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    let pending = state
        .pending_sign
        .lock()
        .expect("pending_sign mutex poisoned")
        .remove(&req.request_token)
        .ok_or_else(|| ApiError::bad_request("unknown or already-used request_token"))?;

    let assertion = raw_assertion_from_request(
        &req.authenticator_data_b64,
        &req.client_data_json_b64,
        &req.signature_b64,
    )?;
    let evidence = pending
        .passkey_evidence(req.issuer_did, assertion)
        .map_err(ApiError::from_sdk_error)?;

    let client = OrbisClient::connect(state.orbis_endpoint.clone())
        .await
        .map_err(ApiError::from_sdk_error)?;
    let result = client
        .submit_sign_with_evidence(pending, evidence)
        .await
        .map_err(ApiError::from_sdk_error)?;

    Ok(Json(SignResponse {
        signature_hex: result.signature,
    }))
}

#[derive(Deserialize)]
struct PreChallengeRequest {
    ring_pk: String,
    object_id: String,
    issuer_did: String,
    derivation_hex: Option<String>,
    salt: Option<String>,
}

#[derive(Serialize)]
struct PreChallengeResponse {
    request_token: String,
    challenge_b64url: String,
}

/// Builds a passkey-authorized PRE challenge — generates the ephemeral
/// reader keypair PRE needs (it has to exist before the challenge can be
/// built, since the challenge embeds `rdr_pk`) via
/// `orbis_sdk::build_pre_challenge`, and holds the result in
/// `AppState::pending_pre` until `/api/pre/decrypt` consumes it.
async fn pre_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PreChallengeRequest>,
) -> Result<Json<PreChallengeResponse>, ApiError> {
    let derivation = req
        .derivation_hex
        .as_deref()
        .map(hex::decode)
        .transpose()
        .map_err(|e| ApiError::bad_request(format!("invalid derivation hex: {e}")))?;

    let pending = orbis_sdk::build_pre_challenge(
        state.chain_id.clone(),
        req.ring_pk,
        req.object_id,
        &req.issuer_did,
        derivation,
        req.salt,
        None,
        None,
    )
    .map_err(ApiError::from_sdk_error)?;

    let challenge_b64url = encode_challenge(&pending.challenge());
    let request_token = hex::encode(rand::random::<[u8; 16]>());
    state
        .pending_pre
        .lock()
        .expect("pending_pre mutex poisoned")
        .insert(request_token.clone(), pending);

    Ok(Json(PreChallengeResponse {
        request_token,
        challenge_b64url,
    }))
}

#[derive(Deserialize)]
struct PreDecryptRequest {
    request_token: String,
    issuer_did: String,
    authenticator_data_b64: String,
    client_data_json_b64: String,
    signature_b64: String,
}

#[derive(Serialize)]
struct PreDecryptResponse {
    /// The decrypted plaintext, as text when it's valid UTF-8, hex
    /// otherwise — this app has no idea what the document's content type
    /// is, so it guesses the friendlier rendering rather than picking one.
    plaintext: String,
    is_hex: bool,
}

/// Finishes a passkey-authorized PRE request given the pending state
/// `/api/pre/challenge` stashed and the WebAuthn assertion a ceremony
/// against its challenge produced — signs the reader-key
/// proof-of-possession transcript, submits the request, and decrypts the
/// result via `orbis_sdk::OrbisClient::submit_pre_with_evidence`.
async fn pre_decrypt(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PreDecryptRequest>,
) -> Result<Json<PreDecryptResponse>, ApiError> {
    let pending = state
        .pending_pre
        .lock()
        .expect("pending_pre mutex poisoned")
        .remove(&req.request_token)
        .ok_or_else(|| ApiError::bad_request("unknown or already-used request_token"))?;

    let assertion = raw_assertion_from_request(
        &req.authenticator_data_b64,
        &req.client_data_json_b64,
        &req.signature_b64,
    )?;
    let evidence = pending.passkey_evidence(req.issuer_did, assertion);

    let client = OrbisClient::connect(state.orbis_endpoint.clone())
        .await
        .map_err(ApiError::from_sdk_error)?;
    let plaintext = client
        .submit_pre_with_evidence(pending, evidence)
        .await
        .map_err(ApiError::from_sdk_error)?;

    match String::from_utf8(plaintext.clone()) {
        Ok(text) => Ok(Json(PreDecryptResponse {
            plaintext: text,
            is_hex: false,
        })),
        Err(_) => Ok(Json(PreDecryptResponse {
            plaintext: hex::encode(plaintext),
            is_hex: true,
        })),
    }
}

fn raw_assertion_from_request(
    authenticator_data_b64: &str,
    client_data_json_b64: &str,
    signature_b64: &str,
) -> Result<RawAssertion, ApiError> {
    Ok(RawAssertion {
        authenticator_data: decode_standard_b64(authenticator_data_b64)
            .map_err(|e| ApiError::bad_request(format!("invalid authenticatorData base64: {e}")))?,
        client_data_json: decode_standard_b64(client_data_json_b64)
            .map_err(|e| ApiError::bad_request(format!("invalid clientDataJSON base64: {e}")))?,
        signature: decode_standard_b64(signature_b64)
            .map_err(|e| ApiError::bad_request(format!("invalid signature base64: {e}")))?,
    })
}

fn decode_standard_b64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
}

fn encode_challenge(challenge: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, challenge)
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    /// Classifies an SDK error into the right HTTP status: a transport
    /// error carries orbis-node's own gRPC status code (an
    /// authentication/ACP rejection maps to 403, anything else to 502,
    /// since this app's own upstream is what failed); every other variant
    /// means the browser caller supplied something malformed or a
    /// cryptographic step failed, which is this app's caller's fault
    /// (400).
    fn from_sdk_error(error: SdkError) -> Self {
        match error {
            SdkError::Transport(status) => {
                let http_status = match status.code() {
                    tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
                        StatusCode::FORBIDDEN
                    }
                    _ => StatusCode::BAD_GATEWAY,
                };
                Self {
                    status: http_status,
                    message: status.message().to_string(),
                }
            }
            SdkError::Connect { .. } | SdkError::Rejected(_) => Self {
                status: StatusCode::BAD_GATEWAY,
                message: error.to_string(),
            },
            _ => Self::bad_request(error.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}
