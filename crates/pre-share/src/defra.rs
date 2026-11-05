//! HTTP client for Defra-backed PRE share storage (ring `pre_share_endpoints`).
//!
//! Talks to a single DefraDB ("edge db") instance over its REST API: provisions
//! the [`PRE_SHARE_COLLECTION`] collection, stores a signed envelope as a
//! document, and fetches a stored envelope back by locator. Shared by the
//! producer side (a PRE responder storing its own share) and the reader side
//! (manifest-driven retrieval), since both need exactly the same two
//! document operations against the same collection.
//!
//! Confirmed against the actual DefraDB REST implementation (not guessed):
//! `POST /api/v0/collections/{name}` is a REST handler that runs the write as
//! a GraphQL mutation internally, but the server already converts any
//! GraphQL-level error into a real, non-200 HTTP status before this client
//! ever sees it — there is no "200 with a hidden error" case to defend
//! against. A duplicate write (same content, same content-addressed docID)
//! comes back as HTTP 409 with a body whose `error` message embeds
//! `"DocID: {id}"`; this client recovers that as a successful store rather
//! than surfacing it as a failure, since it proves the content was already
//! durably written by an earlier attempt whose own response was lost.

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::envelope::SignedStoredShareEnvelope;
use crate::manifest::DefraLocator;

/// Name of the collection every Defra-backed PRE share is stored in.
pub const PRE_SHARE_COLLECTION: &str = "PreShare";

/// SDL for [`PRE_SHARE_COLLECTION`]. `request_id`/`ring_id`/`participant` are
/// queryable for operational visibility via `/api/v0/graphql` — the read
/// path itself always goes by docID (see [`DefraClient::fetch_envelope`]),
/// never by these fields. `envelope` holds the JSON-encoded
/// [`SignedStoredShareEnvelope`] as an opaque string, sidestepping any need
/// to confirm SDL support for a nested/JSON scalar type.
pub const PRE_SHARE_COLLECTION_SDL: &str =
    "type PreShare { request_id: String ring_id: String participant: String envelope: String }";

/// Maximum response body this client will read, regardless of what
/// `Content-Length` claims. Generous relative to a single envelope's
/// realistic size; this is defense-in-depth against a misbehaving endpoint,
/// not a tight budget — `pre_share_endpoints` names infrastructure the ring
/// operator configured themselves, not an arbitrary untrusted peer.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// How long one HTTP attempt may take before `store_envelope` retries —
/// always well under the caller's overall deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Delay between retry attempts within the overall deadline.
const RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// Maximum simultaneous in-flight requests this client issues — bounds a
/// node's fan-out against one Defra endpoint when many PRE requests across
/// rings are in flight concurrently.
const MAX_CONCURRENT_REQUESTS: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum DefraClientError {
    #[error("Defra request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Defra request timed out before succeeding")]
    Timeout,
    #[error("Defra rejected the request ({status}): {message}")]
    Server { status: u16, message: String },
    #[error("Defra response did not match the expected shape: {0}")]
    Malformed(String),
    #[error("Defra response exceeded the maximum allowed size")]
    ResponseTooLarge,
}

/// Queryable fields stored alongside the encoded envelope — never part of
/// the signed content itself. See [`PRE_SHARE_COLLECTION_SDL`].
#[derive(Debug, Clone)]
pub struct PreShareFields {
    pub request_id: String,
    pub ring_id: String,
    /// The responder's node key — named `participant` in the collection
    /// schema to match the original design's queryable-field name.
    pub participant: String,
}

#[derive(Serialize)]
struct PreShareDocument<'a> {
    request_id: &'a str,
    ring_id: &'a str,
    participant: &'a str,
    envelope: String,
}

#[derive(Deserialize)]
struct StoredPreShareDocument {
    envelope: String,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

pub struct DefraClient {
    http: reqwest::Client,
    base_url: Url,
    bearer_token: String,
    concurrency: Arc<Semaphore>,
}

impl DefraClient {
    pub fn new(base_url: Url, bearer_token: String) -> Result<Self, DefraClientError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            base_url,
            bearer_token,
            concurrency: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        })
    }

    fn collection_url(&self, collection: &str) -> Url {
        self.base_url
            .join(&format!("api/v0/collections/{collection}"))
            .expect("collection name is a valid URL path segment")
    }

    fn document_url(&self, collection: &str, doc_id: &str) -> Url {
        self.base_url
            .join(&format!(
                "api/v0/collections/{collection}/document/{doc_id}"
            ))
            .expect("collection name and docID are valid URL path segments")
    }

    /// POSTs `sdl` to provision [`PRE_SHARE_COLLECTION`] (or any other
    /// collection). Idempotent: a 409 "already exists" response — the
    /// expected outcome on every node startup after the first — is success,
    /// not an error.
    pub async fn provision_collection(&self, sdl: &str) -> Result<(), DefraClientError> {
        let url = self
            .base_url
            .join("api/v0/collections")
            .expect("static path is a valid URL");
        let _permit = self
            .concurrency
            .acquire()
            .await
            .expect("semaphore is never closed");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.bearer_token)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(sdl.to_string())
            .send()
            .await?;
        let status = response.status();
        let bytes = read_bounded(response).await?;
        if status.is_success() {
            return Ok(());
        }
        let message = error_message(&bytes);
        if status == StatusCode::CONFLICT && message.to_ascii_lowercase().contains("already exists")
        {
            return Ok(());
        }
        Err(DefraClientError::Server {
            status: status.as_u16(),
            message,
        })
    }

    /// Stores `envelope` under `fields` and returns its content-addressed
    /// locator, retrying within `deadline`. The caller signs `envelope` once
    /// (never re-signed here) so every retry resends byte-identical content
    /// — content-addressing then guarantees the same docID on every attempt,
    /// which is what makes the 409 "already exists" recovery path correct.
    pub async fn store_envelope(
        &self,
        collection: &str,
        fields: PreShareFields,
        envelope: &SignedStoredShareEnvelope,
        deadline: Instant,
    ) -> Result<DefraLocator, DefraClientError> {
        let envelope_json = serde_json::to_string(envelope)
            .map_err(|error| DefraClientError::Malformed(error.to_string()))?;
        let body = PreShareDocument {
            request_id: &fields.request_id,
            ring_id: &fields.ring_id,
            participant: &fields.participant,
            envelope: envelope_json,
        };
        let url = self.collection_url(collection);

        loop {
            if Instant::now() >= deadline {
                return Err(DefraClientError::Timeout);
            }
            if let Some(locator) = self.try_store(&url, &body).await? {
                return Ok(locator);
            }
            tokio::time::sleep(RETRY_BACKOFF).await;
        }
    }

    async fn try_store(
        &self,
        url: &Url,
        body: &PreShareDocument<'_>,
    ) -> Result<Option<DefraLocator>, DefraClientError> {
        let _permit = self
            .concurrency
            .acquire()
            .await
            .expect("semaphore is never closed");
        let response = match self
            .http
            .post(url.clone())
            .bearer_auth(&self.bearer_token)
            .json(body)
            .send()
            .await
        {
            Ok(response) => response,
            // A transport-level failure (never reached the server, or it never
            // responded) is exactly the "committed-write-but-lost-response" case
            // the retry loop exists for — retryable, not a hard failure.
            Err(error) if error.is_timeout() || error.is_connect() => return Ok(None),
            Err(error) => return Err(DefraClientError::Network(error)),
        };

        let status = response.status();
        let bytes = read_bounded(response).await?;

        if status.is_success() {
            let doc_ids: Vec<String> = serde_json::from_slice(&bytes)
                .map_err(|error| DefraClientError::Malformed(error.to_string()))?;
            let doc_id = doc_ids.into_iter().next().ok_or_else(|| {
                DefraClientError::Malformed("add_document returned an empty docID array".into())
            })?;
            return Ok(Some(DefraLocator(doc_id)));
        }

        let message = error_message(&bytes);
        if status == StatusCode::CONFLICT {
            if let Some(doc_id) = parse_already_exists_doc_id(&message) {
                return Ok(Some(DefraLocator(doc_id)));
            }
            // A 409 that isn't "already exists" is a transaction conflict —
            // transient and retryable by definition (Go's own message says so).
            return Ok(None);
        }
        if is_retryable(status) {
            return Ok(None);
        }
        Err(DefraClientError::Server {
            status: status.as_u16(),
            message,
        })
    }

    /// Fetches the envelope stored at `locator`. Single-shot — unlike
    /// `store_envelope`, a read has no idempotency concern to retry around;
    /// callers that want retry-on-transient-failure wrap this themselves.
    pub async fn fetch_envelope(
        &self,
        collection: &str,
        locator: &DefraLocator,
    ) -> Result<SignedStoredShareEnvelope, DefraClientError> {
        let url = self.document_url(collection, &locator.0);
        let _permit = self
            .concurrency
            .acquire()
            .await
            .expect("semaphore is never closed");
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.bearer_token)
            .send()
            .await?;
        let status = response.status();
        let bytes = read_bounded(response).await?;
        if !status.is_success() {
            return Err(DefraClientError::Server {
                status: status.as_u16(),
                message: error_message(&bytes),
            });
        }
        let document: StoredPreShareDocument = serde_json::from_slice(&bytes)
            .map_err(|error| DefraClientError::Malformed(error.to_string()))?;
        serde_json::from_str(&document.envelope)
            .map_err(|error| DefraClientError::Malformed(error.to_string()))
    }
}

async fn read_bounded(response: reqwest::Response) -> Result<Vec<u8>, DefraClientError> {
    if let Some(len) = response.content_length() {
        if len > MAX_RESPONSE_BYTES as u64 {
            return Err(DefraClientError::ResponseTooLarge);
        }
    }
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(DefraClientError::ResponseTooLarge);
    }
    Ok(bytes.to_vec())
}

fn error_message(bytes: &[u8]) -> String {
    serde_json::from_slice::<ErrorBody>(bytes)
        .map(|body| body.error)
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

/// Recognizes `"a document with the given ID already exists. DocID: {id}"`
/// (`crates/db/src/write/autocommit/helpers.rs` in defradb.rs) and recovers
/// the embedded docID. `None` if the message doesn't match — callers must
/// not assume every 409 is this case.
fn parse_already_exists_doc_id(message: &str) -> Option<String> {
    if !message.to_ascii_lowercase().contains("already exists") {
        return None;
    }
    message
        .split("DocID: ")
        .nth(1)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

fn is_retryable(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_and_document_urls_join_correctly_on_a_bare_base() {
        let client = DefraClient::new(
            Url::parse("http://localhost:9181").unwrap(),
            "token".to_string(),
        )
        .unwrap();
        assert_eq!(
            client.collection_url("PreShare").as_str(),
            "http://localhost:9181/api/v0/collections/PreShare"
        );
        assert_eq!(
            client.document_url("PreShare", "bae-abc123").as_str(),
            "http://localhost:9181/api/v0/collections/PreShare/document/bae-abc123"
        );
    }

    #[test]
    fn collection_url_joins_correctly_on_a_base_with_a_path_and_trailing_slash() {
        let client = DefraClient::new(
            Url::parse("http://localhost:9181/defra/").unwrap(),
            "token".to_string(),
        )
        .unwrap();
        assert_eq!(
            client.collection_url("PreShare").as_str(),
            "http://localhost:9181/defra/api/v0/collections/PreShare"
        );
    }

    #[test]
    fn parses_doc_id_from_the_already_exists_message() {
        let message = "a document with the given ID already exists. DocID: bae-c94acbfa-dd53";
        assert_eq!(
            parse_already_exists_doc_id(message),
            Some("bae-c94acbfa-dd53".to_string())
        );
    }

    #[test]
    fn does_not_mistake_an_unrelated_conflict_for_already_exists() {
        assert_eq!(
            parse_already_exists_doc_id("transaction conflict. Please retry"),
            None
        );
    }

    #[test]
    fn error_message_prefers_the_json_error_field_over_raw_bytes() {
        let body = br#"{"error":"a document with the given ID already exists. DocID: bae-1"}"#;
        assert_eq!(
            error_message(body),
            "a document with the given ID already exists. DocID: bae-1"
        );
    }

    #[test]
    fn error_message_falls_back_to_raw_bytes_for_non_json_bodies() {
        assert_eq!(error_message(b"not json"), "not json");
    }

    #[tokio::test]
    async fn store_envelope_returns_timeout_without_attempting_a_request_once_the_deadline_has_passed(
    ) {
        let client = DefraClient::new(
            // Nothing is listening here; a real attempt would hang/fail slowly —
            // if this returns promptly, no request was attempted.
            Url::parse("http://127.0.0.1:1").unwrap(),
            "token".to_string(),
        )
        .unwrap();
        let envelope = crate::test_support::signed_envelope();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.store_envelope(
                PRE_SHARE_COLLECTION,
                PreShareFields {
                    request_id: "req-1".to_string(),
                    ring_id: "ring-1".to_string(),
                    participant: "node-1".to_string(),
                },
                &envelope,
                Instant::now(),
            ),
        )
        .await
        .expect("should return promptly, not hang");

        assert!(matches!(result, Err(DefraClientError::Timeout)));
    }

    // The tests below run against an in-process mock HTTP server
    // (`wiremock`) shaped exactly like the real responses confirmed by
    // reading defradb.rs's own source (see this module's doc comment) —
    // they verify this client's request/retry/parsing logic actually
    // behaves as designed, not just that the helper functions do in
    // isolation. They do not exercise a real DefraDB; that's Step 6's
    // Docker E2E test.

    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Returns `responses[call_count]` (clamped to the last entry), so a
    /// test can script e.g. "fail once, then succeed" against one endpoint
    /// without depending on wiremock's mock-ordering semantics.
    struct Sequence {
        responses: Vec<ResponseTemplate>,
        call: AtomicUsize,
    }

    impl Respond for Sequence {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let index = self.call.fetch_add(1, Ordering::SeqCst);
            self.responses[index.min(self.responses.len() - 1)].clone()
        }
    }

    fn far_future_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[tokio::test]
    async fn store_envelope_succeeds_and_returns_the_docid_from_the_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/collections/PreShare"))
            .respond_with(ResponseTemplate::new(200).set_body_json(["bae-abc123"]))
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        let locator = client
            .store_envelope(
                PRE_SHARE_COLLECTION,
                PreShareFields {
                    request_id: "req-1".to_string(),
                    ring_id: "ring-1".to_string(),
                    participant: "node-1".to_string(),
                },
                &crate::test_support::signed_envelope(),
                far_future_deadline(),
            )
            .await
            .expect("store should succeed");

        assert_eq!(locator, DefraLocator("bae-abc123".to_string()));
    }

    #[tokio::test]
    async fn store_envelope_recovers_the_locator_from_an_already_exists_conflict() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/collections/PreShare"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error": "a document with the given ID already exists. DocID: bae-existing"
            })))
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        let locator = client
            .store_envelope(
                PRE_SHARE_COLLECTION,
                PreShareFields {
                    request_id: "req-1".to_string(),
                    ring_id: "ring-1".to_string(),
                    participant: "node-1".to_string(),
                },
                &crate::test_support::signed_envelope(),
                far_future_deadline(),
            )
            .await
            .expect("an already-exists conflict should be recovered as success");

        assert_eq!(locator, DefraLocator("bae-existing".to_string()));
    }

    #[tokio::test]
    async fn store_envelope_retries_past_a_transaction_conflict_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/collections/PreShare"))
            .respond_with(Sequence {
                responses: vec![
                    ResponseTemplate::new(409).set_body_json(serde_json::json!({
                        "error": "transaction conflict. Please retry"
                    })),
                    ResponseTemplate::new(200).set_body_json(["bae-after-retry"]),
                ],
                call: AtomicUsize::new(0),
            })
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        let locator = client
            .store_envelope(
                PRE_SHARE_COLLECTION,
                PreShareFields {
                    request_id: "req-1".to_string(),
                    ring_id: "ring-1".to_string(),
                    participant: "node-1".to_string(),
                },
                &crate::test_support::signed_envelope(),
                far_future_deadline(),
            )
            .await
            .expect("should retry past the transaction conflict and succeed");

        assert_eq!(locator, DefraLocator("bae-after-retry".to_string()));
    }

    #[tokio::test]
    async fn store_envelope_retries_past_a_5xx_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/collections/PreShare"))
            .respond_with(Sequence {
                responses: vec![
                    ResponseTemplate::new(503).set_body_json(serde_json::json!({
                        "error": "database is closed"
                    })),
                    ResponseTemplate::new(200).set_body_json(["bae-after-5xx"]),
                ],
                call: AtomicUsize::new(0),
            })
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        let locator = client
            .store_envelope(
                PRE_SHARE_COLLECTION,
                PreShareFields {
                    request_id: "req-1".to_string(),
                    ring_id: "ring-1".to_string(),
                    participant: "node-1".to_string(),
                },
                &crate::test_support::signed_envelope(),
                far_future_deadline(),
            )
            .await
            .expect("should retry past the 5xx and succeed");

        assert_eq!(locator, DefraLocator("bae-after-5xx".to_string()));
    }

    #[tokio::test]
    async fn store_envelope_surfaces_a_non_retryable_4xx_as_a_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/collections/PreShare"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "malformed document"
            })))
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        let error = client
            .store_envelope(
                PRE_SHARE_COLLECTION,
                PreShareFields {
                    request_id: "req-1".to_string(),
                    ring_id: "ring-1".to_string(),
                    participant: "node-1".to_string(),
                },
                &crate::test_support::signed_envelope(),
                far_future_deadline(),
            )
            .await
            .expect_err("a 400 should not be retried into success");

        assert!(matches!(
            error,
            DefraClientError::Server { status: 400, .. }
        ));
    }

    #[tokio::test]
    async fn store_envelope_sends_the_bearer_token_and_the_request_id_field() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/collections/PreShare"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer secret-token",
            ))
            .and(body_string_contains("\"request_id\":\"req-42\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(["bae-ok"]))
            .mount(&server)
            .await;

        let client = DefraClient::new(
            Url::parse(&server.uri()).unwrap(),
            "secret-token".to_string(),
        )
        .unwrap();
        client
            .store_envelope(
                PRE_SHARE_COLLECTION,
                PreShareFields {
                    request_id: "req-42".to_string(),
                    ring_id: "ring-1".to_string(),
                    participant: "node-1".to_string(),
                },
                &crate::test_support::signed_envelope(),
                far_future_deadline(),
            )
            .await
            .expect("the matched request should have been sent");
    }

    #[tokio::test]
    async fn fetch_envelope_round_trips_a_stored_document() {
        let envelope = crate::test_support::signed_envelope();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v0/collections/PreShare/document/bae-abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_docID": "bae-abc123",
                "request_id": "req-1",
                "ring_id": "ring-1",
                "participant": "node-1",
                "envelope": serde_json::to_string(&envelope).unwrap(),
            })))
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        let fetched = client
            .fetch_envelope(
                PRE_SHARE_COLLECTION,
                &DefraLocator("bae-abc123".to_string()),
            )
            .await
            .expect("fetch should succeed");

        assert_eq!(fetched, envelope);
    }

    #[tokio::test]
    async fn fetch_envelope_surfaces_a_not_found_as_a_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v0/collections/PreShare/document/bae-missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": "document not found or not authorized to access"
            })))
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        let error = client
            .fetch_envelope(
                PRE_SHARE_COLLECTION,
                &DefraLocator("bae-missing".to_string()),
            )
            .await
            .expect_err("a missing document should be a server error, not a panic");

        assert!(matches!(
            error,
            DefraClientError::Server { status: 404, .. }
        ));
    }

    #[tokio::test]
    async fn provision_collection_succeeds_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/collections"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        client
            .provision_collection(PRE_SHARE_COLLECTION_SDL)
            .await
            .expect("provisioning should succeed");
    }

    #[tokio::test]
    async fn provision_collection_is_idempotent_when_it_already_exists() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v0/collections"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error": "collection already exists. Name: PreShare"
            })))
            .mount(&server)
            .await;

        let client =
            DefraClient::new(Url::parse(&server.uri()).unwrap(), "token".to_string()).unwrap();
        client
            .provision_collection(PRE_SHARE_COLLECTION_SDL)
            .await
            .expect("an already-exists conflict should be treated as success");
    }
}
