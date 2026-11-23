//! Passkey signing reference application.
//!
//! Serves a small browser UI (`web/`) that registers a passkey and uses it
//! to authorize a threshold Sign request — no password, no JWT, no
//! separate enrollment step: the passkey's own public key *is* the
//! identity ACP grants or revokes directly (see `orbis-webauthn`'s and
//! `orbis-integration-core`'s doc comments for why).
//!
//! This process is a thin bridge, nothing more: browsers can't speak gRPC
//! directly, so it turns the browser's WebAuthn output into a
//! `StartSignRequest` and forwards it to orbis-node. It never verifies
//! anything itself — every ring node does that independently; a verification
//! result produced here would not be proof for anyone else.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use orbis_integration_core::{CanonicalOperation, SignOperation};
use p256::pkcs8::DecodePublicKey;
use proto::v0::sign::sign_service_client::SignServiceClient;
use proto::v0::sign::{StartSignRequest, WebAuthnAssertion};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Parser, Debug, Clone)]
#[command(name = "passkey-sign")]
#[command(about = "Passkey signing reference application")]
struct Args {
    /// Address this server binds to.
    #[arg(long, default_value = "127.0.0.1:8787")]
    addr: String,
    /// orbis-node gRPC endpoint to forward Sign requests to.
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
    /// PRE's reader keypair + reader-authorization transcript have to be
    /// decided *before* the WebAuthn challenge can be built (the challenge
    /// embeds `rdr_pk`), but the request can't be submitted until *after*
    /// the browser's ceremony produces an assertion — so, unlike Sign's
    /// endpoints, this app does need to hold state across the two PRE
    /// calls. A plain in-memory map, not persisted or swept: fine for a
    /// single-process reference app, not a production pattern.
    pending_pre: std::sync::Mutex<std::collections::HashMap<String, cli_tool::PendingPasskeyPre>>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let addr = args.addr.clone();
    let state = Arc::new(AppState {
        orbis_endpoint: args.orbis_endpoint,
        rp_id: args.rp_id,
        origin: args.origin,
        chain_id: args.chain_id,
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
    println!("passkey-sign reference app listening on http://{addr}");
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
    challenge_b64url: String,
    issued_at: u64,
    expiry: u64,
    nonce_hex: String,
}

/// Builds the exact challenge the browser must embed in its WebAuthn
/// ceremony — a fresh `issued_at`/`expiry`/nonce plus this request's own
/// `derivation_id`/message digest, canonically encoded
/// (`SignOperation::canonical_bytes`). The node independently recomputes
/// and compares this same encoding; nothing here needs to be remembered
/// between this call and `/api/sign`, so this app keeps no session state.
async fn challenge(Json(req): Json<ChallengeRequest>) -> Result<Json<ChallengeResponse>, ApiError> {
    let message = hex::decode(&req.message_hex)
        .map_err(|e| ApiError::bad_request(format!("invalid message hex: {e}")))?;
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::internal(format!("system clock before epoch: {e}")))?
        .as_secs();
    let expiry = issued_at + 300;
    let nonce: [u8; 16] = rand::random();
    let operation = SignOperation {
        derivation_id: req.derivation_id,
        message_sha256: Sha256::digest(&message).to_vec(),
        expiry,
        nonce,
    };
    let challenge_b64url = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        operation.canonical_bytes(),
    );
    Ok(Json(ChallengeResponse {
        challenge_b64url,
        issued_at,
        expiry,
        nonce_hex: hex::encode(nonce),
    }))
}

#[derive(Deserialize)]
struct SignRequest {
    derivation_id: String,
    message_hex: String,
    issuer_did: String,
    authenticator_data_b64: String,
    client_data_json_b64: String,
    signature_b64: String,
    issued_at: u64,
    expiry: u64,
    nonce_hex: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature_hex: String,
}

async fn sign(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    let message = hex::decode(&req.message_hex)
        .map_err(|e| ApiError::bad_request(format!("invalid message hex: {e}")))?;
    let authenticator_data = decode_standard_b64(&req.authenticator_data_b64)
        .map_err(|e| ApiError::bad_request(format!("invalid authenticatorData base64: {e}")))?;
    let client_data_json = decode_standard_b64(&req.client_data_json_b64)
        .map_err(|e| ApiError::bad_request(format!("invalid clientDataJSON base64: {e}")))?;
    let signature = decode_standard_b64(&req.signature_b64)
        .map_err(|e| ApiError::bad_request(format!("invalid signature base64: {e}")))?;
    let nonce = hex::decode(&req.nonce_hex)
        .map_err(|e| ApiError::bad_request(format!("invalid nonce hex: {e}")))?;

    let mut client = SignServiceClient::connect(state.orbis_endpoint.clone())
        .await
        .map_err(|e| ApiError::internal(format!("failed to connect to orbis-node: {e}")))?;

    let response = client
        .start_sign(StartSignRequest {
            message,
            derivation_id: req.derivation_id,
            valid_window: None,
            webauthn_assertion: Some(WebAuthnAssertion {
                issuer_did: req.issuer_did,
                authenticator_data,
                client_data_json,
                signature,
                issued_at: req.issued_at,
                expiry: req.expiry,
                nonce,
            }),
        })
        .await
        .map_err(ApiError::from_status)?;

    Ok(Json(SignResponse {
        signature_hex: response.into_inner().signature,
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
/// `cli_tool::build_passkey_pre_challenge`, and holds the result in
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

    let pending = cli_tool::build_passkey_pre_challenge(
        state.chain_id.clone(),
        req.ring_pk,
        req.object_id,
        &req.issuer_did,
        derivation,
        req.salt,
        None,
        None,
    )
    .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let challenge_b64url = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        pending.challenge(),
    );
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
/// result via `cli_tool::finish_passkey_pre`.
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

    let authenticator_data = decode_standard_b64(&req.authenticator_data_b64)
        .map_err(|e| ApiError::bad_request(format!("invalid authenticatorData base64: {e}")))?;
    let client_data_json = decode_standard_b64(&req.client_data_json_b64)
        .map_err(|e| ApiError::bad_request(format!("invalid clientDataJSON base64: {e}")))?;
    let signature = decode_standard_b64(&req.signature_b64)
        .map_err(|e| ApiError::bad_request(format!("invalid signature base64: {e}")))?;

    let assertion = orbis_webauthn::RawAssertion {
        authenticator_data,
        client_data_json,
        signature,
    };

    let plaintext = cli_tool::finish_passkey_pre(
        state.orbis_endpoint.clone(),
        pending,
        req.issuer_did,
        assertion,
    )
    .await
    .map_err(|e| ApiError::bad_request(e.to_string()))?;

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

fn decode_standard_b64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
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

    fn from_status(status: tonic::Status) -> Self {
        let http_status = match status.code() {
            tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_GATEWAY,
        };
        Self {
            status: http_status,
            message: status.message().to_string(),
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
