//! Email document decryption reference application.
//!
//! Serves a small browser UI (`web/`) that uses a DKIM-signed email reply
//! to authorize a threshold Sign request, or a PRE decrypt — no WebAuthn
//! ceremony, no JWT, no password, no separate enrollment step: a person's
//! own mailbox *is* the identity ACP grants or revokes (as
//! `did:key:sha256(normalized address)` — see `orbis_email`'s own doc
//! comment for why it wears that prefix).
//!
//! Unlike `passkey-sign`, there's no in-browser ceremony here: this
//! process actually sends the challenge email (SMTP, via `lettre`) and,
//! on request, checks the same mailbox for the reply (IMAP, via
//! `async-imap`) — the two pieces `orbis-email`'s own design deliberately
//! left to an example app. Either way, this app never verifies the DKIM
//! signature itself; every ring node does that independently, exactly
//! like `passkey-sign` never verifies a WebAuthn assertion itself.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use futures::StreamExt;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use orbis_sdk::{OrbisClient, PendingPre, PendingSign, SdkError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Parser, Debug, Clone)]
#[command(name = "email-decrypt")]
#[command(about = "Email document decryption reference application")]
struct Args {
    /// Address this server binds to.
    #[arg(long, default_value = "127.0.0.1:8788")]
    addr: String,
    /// orbis-node gRPC endpoint to forward Sign/PRE requests to.
    #[arg(long, env = "ORBIS_ENDPOINT", default_value = "http://127.0.0.1:50051")]
    orbis_endpoint: String,
    /// Chain id the ring's PRE reader-key proof-of-possession transcript
    /// binds to — must match the ring's own chain.
    #[arg(long, env = "ORBIS_CHAIN_ID")]
    chain_id: String,
    /// The ring's own mailbox: sends every challenge email from this
    /// address, and is the inbox "check for reply" polls. A real Gmail
    /// address with 2FA enabled — see README.md for the App Password this
    /// needs (the regular account password will not work over SMTP/IMAP).
    #[arg(long, env = "GMAIL_ADDRESS")]
    gmail_address: String,
    /// Gmail App Password for `gmail_address` (not the account password).
    #[arg(long, env = "GMAIL_APP_PASSWORD", hide_env_values = true)]
    gmail_app_password: String,
}

/// A Sign challenge awaiting its DKIM-signed reply.
struct PendingEmailSign {
    pending: PendingSign,
    claimed_address: String,
}

/// A PRE challenge awaiting its DKIM-signed reply.
struct PendingEmailPre {
    pending: PendingPre,
    claimed_address: String,
}

struct AppState {
    orbis_endpoint: String,
    chain_id: String,
    gmail_address: String,
    gmail_app_password: String,
    /// Keyed by `request_token`, which doubles as the challenge email's
    /// `Message-ID` local part — see `send_challenge_email`'s own doc
    /// comment for why. Plain in-memory maps, not persisted or swept: fine
    /// for a single-process reference app, not a production pattern (see
    /// `passkey-sign`'s identical `AppState` doc comment).
    pending_sign: std::sync::Mutex<std::collections::HashMap<String, PendingEmailSign>>,
    pending_pre: std::sync::Mutex<std::collections::HashMap<String, PendingEmailPre>>,
}

#[tokio::main]
async fn main() {
    // Loaded from the package's own directory, not the process's current
    // working directory — this app is just as often launched from the
    // workspace root (`cargo run -p email-decrypt`) as from its own
    // directory, and `.env` always lives next to this crate's Cargo.toml.
    // A missing file is a silent no-op: real env vars still work without
    // one.
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));

    let args = Args::parse();
    let addr = args.addr.clone();
    let state = Arc::new(AppState {
        orbis_endpoint: args.orbis_endpoint,
        chain_id: args.chain_id,
        gmail_address: args.gmail_address,
        gmail_app_password: args.gmail_app_password,
        pending_sign: std::sync::Mutex::new(std::collections::HashMap::new()),
        pending_pre: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/api/email-did", post(email_did))
        .route("/api/sign/challenge", post(sign_challenge))
        .route("/api/sign/check-reply", post(sign_check_reply))
        .route("/api/pre/challenge", post(pre_challenge))
        .route("/api/pre/check-reply", post(pre_check_reply))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind HTTP listener");
    println!("email-decrypt reference app listening on http://{addr}");
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

/// `did:key:sha256(normalized address)` — the identity an email-authorized
/// request authenticates as, replicated here (not imported: it's a
/// private implementation detail of `orbis_email::build_token`) exactly
/// as `cli_tool::email_issuer_did` and the Docker e2e scenarios' own
/// `email_issuer_id` already do. Needed up front for PRE only, to pass as
/// `issuer_did` into `orbis_sdk::build_pre_challenge` before the challenge
/// exists; Sign resolves its own issuer from the verified reply alone and
/// never needs this app to compute it.
fn email_issuer_did(address: &str) -> String {
    let normalized = address.trim().to_lowercase();
    format!(
        "did:key:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    )
}

#[derive(Deserialize)]
struct EmailDidRequest {
    address: String,
}

#[derive(Serialize)]
struct EmailDidResponse {
    did: String,
}

/// Pure lookup, no email sent: the identity a given address would
/// authenticate as, so it can be granted ACP permission ahead of time —
/// `email_issuer_did` is a pure function of the address alone, so this
/// needs no state and never touches orbis-node or Gmail.
async fn email_did(Json(req): Json<EmailDidRequest>) -> Json<EmailDidResponse> {
    Json(EmailDidResponse {
        did: email_issuer_did(&req.address),
    })
}

/// Wraps `challenge_text` in copy-paste delimiters, mirroring PEM's own
/// "-----BEGIN PUBLIC KEY-----"/"-----END PUBLIC KEY-----" convention —
/// unambiguous at a glance exactly which lines to copy into a reply,
/// instead of a person having to eyeball where the relevant text starts
/// and stops in an email. Verification (`orbis_email::body_contains_text`)
/// is still a plain substring search for `challenge_text` alone; the
/// delimiter lines carry no meaning to it, so copying them along with the
/// inner text (encouraged — it's the whole point) is harmless.
fn confirmation_block(challenge_text: &str) -> String {
    format!(
        "-----BEGIN ORBIS CONFIRMATION-----\n{challenge_text}-----END ORBIS CONFIRMATION-----\n"
    )
}

/// Sends the challenge email, returning the fresh `request_token` this
/// challenge is now stashed under — also the challenge email's own
/// `Message-ID` local part (`<token@email-decrypt.orbis.local>`), so
/// `check_imap_for_reply` can later find the reply by searching for an
/// `In-Reply-To` header naming that exact id: a real mail client fills in
/// `In-Reply-To`/`References` from the message it's replying to
/// automatically, so this needs no cooperation from the person beyond
/// hitting "Reply."
async fn send_challenge_email(
    state: &AppState,
    to_address: &str,
    subject: &str,
    challenge_text: &str,
) -> Result<String, ApiError> {
    let request_token = hex::encode(rand::random::<[u8; 16]>());
    let message_id = format!("<{request_token}@email-decrypt.orbis.local>");

    let body = format!(
        "An Orbis request needs your confirmation.\n\n\
         Reply to this email. Copy everything between (and including) the \
         BEGIN/END lines below into your reply exactly as shown, then send:\n\n\
         {}",
        confirmation_block(challenge_text)
    );

    let email =
        Message::builder()
            .from(state.gmail_address.parse().map_err(|e| {
                ApiError::internal(format!("invalid configured gmail_address: {e}"))
            })?)
            .to(to_address
                .parse()
                .map_err(|e| ApiError::bad_request(format!("invalid recipient address: {e}")))?)
            .subject(subject)
            .message_id(Some(message_id))
            .body(body)
            .map_err(|e| ApiError::internal(format!("failed to build challenge email: {e}")))?;

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay("smtp.gmail.com")
        .map_err(|e| ApiError::internal(format!("failed to configure SMTP relay: {e}")))?
        .credentials(Credentials::new(
            state.gmail_address.clone(),
            state.gmail_app_password.clone(),
        ))
        .build();
    mailer
        .send(email)
        .await
        .map_err(|e| ApiError::internal(format!("failed to send challenge email: {e}")))?;

    Ok(request_token)
}

/// One-shot IMAP check for a reply to `request_token`'s challenge email —
/// the "check for reply" button's entire job, not a background poll. A
/// miss returns `Ok(None)`, not an error: "not here yet" is an expected,
/// retryable outcome, and the button itself is the retry mechanism.
///
/// Callers must confirm `request_token` is a real, still-pending entry
/// *before* calling this — it's embedded verbatim into the raw IMAP
/// `SEARCH` command line below, and this app's own `request_token`s are
/// always exactly the 32 lowercase hex characters `hex::encode` produces,
/// never anything an IMAP query could misparse. Checking pending-map
/// membership first both rejects a request for a token that was never
/// issued (or already consumed) before any IMAP round trip, and, as a
/// side effect, guarantees the string reaching the query below is one of
/// ours — see the call sites.
async fn check_imap_for_reply(
    state: &AppState,
    request_token: &str,
) -> Result<Option<Vec<u8>>, ApiError> {
    let message_id = format!("<{request_token}@email-decrypt.orbis.local>");

    // `async-imap` has no all-in-one `connect()` helper (unlike lettre's
    // SMTP side) — it expects the caller to open the TCP+TLS stream
    // itself and hand it to `Client::new`.
    let tcp_stream = tokio::net::TcpStream::connect(("imap.gmail.com", 993))
        .await
        .map_err(|e| ApiError::internal(format!("failed to connect to IMAP: {e}")))?;
    let tls_stream = async_native_tls::connect("imap.gmail.com", tcp_stream)
        .await
        .map_err(|e| ApiError::internal(format!("failed to establish IMAP TLS: {e}")))?;
    let client = async_imap::Client::new(tls_stream);
    let mut session = client
        .login(&state.gmail_address, &state.gmail_app_password)
        .await
        .map_err(|(e, _client)| ApiError::internal(format!("IMAP login failed: {e}")))?;

    let select_result = session.select("INBOX").await;
    if let Err(e) = select_result {
        let _ = session.logout().await;
        return Err(ApiError::internal(format!("failed to select INBOX: {e}")));
    }

    // RFC 3501's standard `HEADER <field-name> <string>` search key — not
    // an async-imap-specific feature, so this works against any
    // IMAP4rev1 server, Gmail's included.
    let search_query = format!("HEADER In-Reply-To \"{message_id}\"");
    let sequence_numbers = match session.search(&search_query).await {
        Ok(numbers) => numbers,
        Err(e) => {
            let _ = session.logout().await;
            return Err(ApiError::internal(format!("IMAP search failed: {e}")));
        }
    };

    // `.max()`, not an arbitrary `HashSet` entry: if more than one message
    // matches (e.g. the person replied twice — once with a typo, then a
    // corrected follow-up), the highest sequence number is the most
    // recently arrived one, the one actually worth trying.
    let Some(&sequence_number) = sequence_numbers.iter().max() else {
        let _ = session.logout().await;
        return Ok(None);
    };

    // `BODY.PEEK[]`, not `BODY[]`/`RFC822`: fetches the entire raw
    // message (header intact, needed for the DKIM-Signature header
    // downstream) without marking it `\Seen` as a side effect.
    let raw_message = {
        let mut messages = session
            .fetch(sequence_number.to_string(), "BODY.PEEK[]")
            .await
            .map_err(|e| ApiError::internal(format!("IMAP fetch failed: {e}")))?;
        let mut raw_message = None;
        while let Some(fetch) = messages.next().await {
            let fetch = fetch.map_err(|e| ApiError::internal(format!("IMAP fetch failed: {e}")))?;
            if let Some(body) = fetch.body() {
                raw_message = Some(body.to_vec());
            }
        }
        raw_message
    };

    let _ = session.logout().await;
    Ok(raw_message)
}

#[derive(Deserialize)]
struct SignChallengeRequest {
    derivation_id: String,
    message_hex: String,
    claimed_address: String,
}

#[derive(Serialize)]
struct SignChallengeResponse {
    request_token: String,
    confirmation_block: String,
}

/// Builds a Sign challenge and emails it to `claimed_address` — holds the
/// result, keyed by the fresh `request_token` `send_challenge_email`
/// returns, until `/api/sign/check-reply` consumes it.
async fn sign_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignChallengeRequest>,
) -> Result<Json<SignChallengeResponse>, ApiError> {
    let message = hex::decode(&req.message_hex)
        .map_err(|e| ApiError::bad_request(format!("invalid message hex: {e}")))?;

    let pending = orbis_sdk::build_sign_challenge(req.derivation_id, message, None, None)
        .map_err(ApiError::from_sdk_error)?;
    let challenge_text = pending.email_challenge_text();

    let request_token = send_challenge_email(
        &state,
        &req.claimed_address,
        "Confirm this Orbis Sign request",
        &challenge_text,
    )
    .await?;

    state
        .pending_sign
        .lock()
        .expect("pending_sign mutex poisoned")
        .insert(
            request_token.clone(),
            PendingEmailSign {
                pending,
                claimed_address: req.claimed_address,
            },
        );

    Ok(Json(SignChallengeResponse {
        request_token,
        confirmation_block: confirmation_block(&challenge_text),
    }))
}

#[derive(Deserialize)]
struct CheckReplyRequest {
    request_token: String,
}

#[derive(Serialize)]
struct SignCheckReplyResponse {
    found: bool,
    signature_hex: Option<String>,
}

/// Checks for, and if present finishes, the Sign request `/api/sign/challenge`
/// started. Order matters here: the pending entry is only ever removed
/// once a reply has actually been found *and* the node connection is
/// already up, so a request for an unknown token, a "not replied yet"
/// miss, or a transient connection failure all leave it untouched for a
/// later retry — only an attempted, rejected submission consumes it (see
/// `check_imap_for_reply`'s own doc comment for why checking it exists
/// here first matters beyond that).
async fn sign_check_reply(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckReplyRequest>,
) -> Result<Json<SignCheckReplyResponse>, ApiError> {
    if !state
        .pending_sign
        .lock()
        .expect("pending_sign mutex poisoned")
        .contains_key(&req.request_token)
    {
        return Err(ApiError::bad_request(
            "unknown or already-used request_token",
        ));
    }

    let client = OrbisClient::connect(state.orbis_endpoint.clone())
        .await
        .map_err(ApiError::from_sdk_error)?;

    let raw_message = check_imap_for_reply(&state, &req.request_token).await?;
    let Some(raw_message) = raw_message else {
        return Ok(Json(SignCheckReplyResponse {
            found: false,
            signature_hex: None,
        }));
    };

    let PendingEmailSign {
        pending,
        claimed_address,
    } = state
        .pending_sign
        .lock()
        .expect("pending_sign mutex poisoned")
        .remove(&req.request_token)
        .ok_or_else(|| ApiError::bad_request("unknown or already-used request_token"))?;

    let evidence = pending
        .email_evidence(claimed_address, raw_message)
        .map_err(ApiError::from_sdk_error)?;

    let result = client
        .submit_sign_with_evidence(pending, evidence)
        .await
        .map_err(ApiError::from_sdk_error)?;

    Ok(Json(SignCheckReplyResponse {
        found: true,
        signature_hex: Some(result.signature),
    }))
}

#[derive(Deserialize)]
struct PreChallengeRequest {
    ring_pk: String,
    object_id: String,
    claimed_address: String,
    derivation_hex: Option<String>,
    salt: Option<String>,
}

#[derive(Serialize)]
struct PreChallengeResponse {
    request_token: String,
    confirmation_block: String,
}

/// Builds a PRE challenge and emails it to `claimed_address` — generates
/// the ephemeral reader keypair PRE needs (it has to exist before the
/// challenge can be built, since the challenge embeds `rdr_pk`) via
/// `orbis_sdk::build_pre_challenge`, and holds the result in
/// `AppState::pending_pre` until `/api/pre/check-reply` consumes it.
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
    let issuer_did = email_issuer_did(&req.claimed_address);

    let pending = orbis_sdk::build_pre_challenge(
        state.chain_id.clone(),
        req.ring_pk,
        req.object_id,
        &issuer_did,
        derivation,
        req.salt,
        None,
        None,
    )
    .map_err(ApiError::from_sdk_error)?;
    let challenge_text = pending.email_challenge_text();

    let request_token = send_challenge_email(
        &state,
        &req.claimed_address,
        "Confirm this Orbis decrypt request",
        &challenge_text,
    )
    .await?;

    state
        .pending_pre
        .lock()
        .expect("pending_pre mutex poisoned")
        .insert(
            request_token.clone(),
            PendingEmailPre {
                pending,
                claimed_address: req.claimed_address,
            },
        );

    Ok(Json(PreChallengeResponse {
        request_token,
        confirmation_block: confirmation_block(&challenge_text),
    }))
}

#[derive(Serialize)]
struct PreCheckReplyResponse {
    found: bool,
    /// The decrypted plaintext, as text when it's valid UTF-8, hex
    /// otherwise — this app has no idea what the document's content type
    /// is, so it guesses the friendlier rendering rather than picking one.
    plaintext: Option<String>,
    is_hex: bool,
}

/// Checks for, and if present finishes, the PRE request `/api/pre/challenge`
/// started — signs the reader-key proof-of-possession transcript, submits
/// the request, and decrypts the result via
/// `orbis_sdk::OrbisClient::submit_pre_with_evidence`. The ephemeral
/// reader keypair and the decryption itself both stay server-side here,
/// exactly as `passkey-sign`'s own PRE flow already does. Same ordering
/// guarantee as `sign_check_reply`: the pending entry is only removed
/// once a reply has actually been found and the node connection is
/// already up.
async fn pre_check_reply(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckReplyRequest>,
) -> Result<Json<PreCheckReplyResponse>, ApiError> {
    if !state
        .pending_pre
        .lock()
        .expect("pending_pre mutex poisoned")
        .contains_key(&req.request_token)
    {
        return Err(ApiError::bad_request(
            "unknown or already-used request_token",
        ));
    }

    let client = OrbisClient::connect(state.orbis_endpoint.clone())
        .await
        .map_err(ApiError::from_sdk_error)?;

    let raw_message = check_imap_for_reply(&state, &req.request_token).await?;
    let Some(raw_message) = raw_message else {
        return Ok(Json(PreCheckReplyResponse {
            found: false,
            plaintext: None,
            is_hex: false,
        }));
    };

    let PendingEmailPre {
        pending,
        claimed_address,
    } = state
        .pending_pre
        .lock()
        .expect("pending_pre mutex poisoned")
        .remove(&req.request_token)
        .ok_or_else(|| ApiError::bad_request("unknown or already-used request_token"))?;

    let evidence = pending.email_evidence(claimed_address, raw_message);

    let plaintext = client
        .submit_pre_with_evidence(pending, evidence)
        .await
        .map_err(ApiError::from_sdk_error)?;

    match String::from_utf8(plaintext.clone()) {
        Ok(text) => Ok(Json(PreCheckReplyResponse {
            found: true,
            plaintext: Some(text),
            is_hex: false,
        })),
        Err(_) => Ok(Json(PreCheckReplyResponse {
            found: true,
            plaintext: Some(hex::encode(plaintext)),
            is_hex: true,
        })),
    }
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

    /// Classifies an SDK error into the right HTTP status — identical
    /// shape to `passkey-sign`'s own `ApiError::from_sdk_error`: a
    /// transport error carries orbis-node's own gRPC status code (an
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
