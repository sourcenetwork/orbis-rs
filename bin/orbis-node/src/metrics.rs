//! Prometheus metrics for the Orbis node
//!
//! Provides metrics for gRPC services, DKG protocol, and PRE operations.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Encoder, Gauge,
    HistogramVec, TextEncoder,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::TcpListener;

lazy_static! {
    // ============================================================================
    // gRPC Service Metrics
    // ============================================================================

    pub static ref GRPC_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "grpc_requests_total",
        "Total number of gRPC requests",
        &["service", "method", "status"]
    )
    .expect("failed to register grpc_requests_total");

    pub static ref GRPC_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "grpc_request_duration_seconds",
        "gRPC request duration in seconds",
        &["service", "method"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("failed to register grpc_request_duration_seconds");

    // ============================================================================
    // DKG Protocol Metrics
    // ============================================================================

    pub static ref DKG_SESSIONS_TOTAL: CounterVec = register_counter_vec!(
        "dkg_sessions_total",
        "Total number of DKG sessions",
        &["status"]
    )
    .expect("failed to register dkg_sessions_total");

    pub static ref DKG_ACTIVE_SESSIONS: Gauge = register_gauge!(
        "dkg_active_sessions",
        "Number of currently active DKG sessions"
    )
    .expect("failed to register dkg_active_sessions");

    pub static ref DKG_PHASE_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "dkg_phase_duration_seconds",
        "Duration of DKG phases in seconds",
        &["phase"],
        vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
    )
    .expect("failed to register dkg_phase_duration_seconds");

    pub static ref DKG_MESSAGES_TOTAL: CounterVec = register_counter_vec!(
        "dkg_messages_total",
        "Total number of DKG protocol messages",
        &["message_type", "direction"]
    )
    .expect("failed to register dkg_messages_total");

    pub static ref DKG_ABANDONED_SESSIONS: Gauge = register_gauge!(
        "dkg_abandoned_sessions",
        "Number of DKG sessions abandoned"
    )
    .expect("failed to register dkg_abandoned_sessions");

    // ============================================================================
    // PRE Protocol Metrics
    // ============================================================================

    pub static ref PRE_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "pre_requests_total",
        "Total number of PRE requests",
        &["status"]
    )
    .expect("failed to register pre_requests_total");

    pub static ref PRE_ACTIVE_REQUESTS: Gauge = register_gauge!(
        "pre_active_requests",
        "Number of currently active PRE requests"
    )
    .expect("failed to register pre_active_requests");

    pub static ref PRE_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "pre_request_duration_seconds",
        "PRE request duration in seconds",
        &[],
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .expect("failed to register pre_request_duration_seconds");

    pub static ref PRE_MESSAGES_TOTAL: CounterVec = register_counter_vec!(
        "pre_messages_total",
        "Total number of PRE protocol messages",
        &["message_type", "direction"]
    )
    .expect("failed to register pre_messages_total");

    // ============================================================================
    // Sign (Threshold BLS Signing) Metrics
    // ============================================================================

    pub static ref SIGN_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "sign_requests_total",
        "Total number of threshold signing requests",
        &["status"]
    )
    .expect("failed to register sign_requests_total");

    pub static ref SIGN_ACTIVE_REQUESTS: Gauge = register_gauge!(
        "sign_active_requests",
        "Number of currently active signing requests"
    )
    .expect("failed to register sign_active_requests");

    pub static ref SIGN_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "sign_request_duration_seconds",
        "Signing request duration in seconds",
        &[],
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .expect("failed to register sign_request_duration_seconds");

    pub static ref SIGN_MESSAGES_TOTAL: CounterVec = register_counter_vec!(
        "sign_messages_total",
        "Total number of signing protocol messages",
        &["message_type", "direction"]
    )
    .expect("failed to register sign_messages_total");

    pub static ref SIGN_ABANDONED_STATES: Gauge = register_gauge!(
        "sign_abandoned_states",
        "Number of sign states abandoned (expired nonces or stale responses)"
    )
    .expect("failed to register sign_abandoned_states");

    // ============================================================================
    // StoreSecret Metrics
    // ============================================================================

    pub static ref STORE_SECRET_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "store_secret_requests_total",
        "Total number of StoreSecret requests",
        &["status"]
    )
    .expect("failed to register store_secret_requests_total");

    pub static ref STORE_SECRET_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "store_secret_request_duration_seconds",
        "StoreSecret request duration in seconds",
        &[],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .expect("failed to register store_secret_request_duration_seconds");

    // ============================================================================
    // Node Health Metrics
    // ============================================================================

    pub static ref NODE_INFO: Gauge = register_gauge!(
        "node_info",
        "Node information (always 1, use labels for metadata)"
    )
    .expect("failed to register node_info");
}

/// Force initialization of all metrics. Call early in startup so any
/// duplicate-name panic crashes the process instead of silently killing a task.
pub fn init() {
    lazy_static::initialize(&GRPC_REQUESTS_TOTAL);
    lazy_static::initialize(&GRPC_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&DKG_SESSIONS_TOTAL);
    lazy_static::initialize(&DKG_ACTIVE_SESSIONS);
    lazy_static::initialize(&DKG_PHASE_DURATION_SECONDS);
    lazy_static::initialize(&DKG_MESSAGES_TOTAL);
    lazy_static::initialize(&DKG_ABANDONED_SESSIONS);
    lazy_static::initialize(&PRE_REQUESTS_TOTAL);
    lazy_static::initialize(&PRE_ACTIVE_REQUESTS);
    lazy_static::initialize(&PRE_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&PRE_MESSAGES_TOTAL);
    lazy_static::initialize(&SIGN_REQUESTS_TOTAL);
    lazy_static::initialize(&SIGN_ACTIVE_REQUESTS);
    lazy_static::initialize(&SIGN_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&SIGN_MESSAGES_TOTAL);
    lazy_static::initialize(&SIGN_ABANDONED_STATES);
    lazy_static::initialize(&STORE_SECRET_REQUESTS_TOTAL);
    lazy_static::initialize(&STORE_SECRET_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&NODE_INFO);
}

// ============================================================================
// Helper functions for recording metrics
// ============================================================================

/// Timer guard for measuring request/operation duration
pub struct Timer {
    start: Instant,
    histogram: &'static HistogramVec,
    labels: Vec<String>,
}

impl Timer {
    pub fn start(histogram: &'static HistogramVec, labels: Vec<String>) -> Self {
        Self {
            start: Instant::now(),
            histogram,
            labels,
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        let label_refs: Vec<&str> = self.labels.iter().map(|s| s.as_str()).collect();
        self.histogram
            .with_label_values(&label_refs)
            .observe(duration);
    }
}

/// Record a gRPC request
pub fn record_grpc_request(service: &str, method: &str, status: &str, duration_secs: f64) {
    GRPC_REQUESTS_TOTAL
        .with_label_values(&[service, method, status])
        .inc();
    GRPC_REQUEST_DURATION_SECONDS
        .with_label_values(&[service, method])
        .observe(duration_secs);
}

/// Record DKG session started
pub fn record_dkg_session_started() {
    DKG_SESSIONS_TOTAL.with_label_values(&["started"]).inc();
    DKG_ACTIVE_SESSIONS.inc();
}

/// Record DKG session completed
pub fn record_dkg_session_completed() {
    DKG_SESSIONS_TOTAL.with_label_values(&["completed"]).inc();
    DKG_ACTIVE_SESSIONS.dec();
}

/// Record DKG session failed
pub fn record_dkg_session_failed() {
    DKG_SESSIONS_TOTAL.with_label_values(&["failed"]).inc();
    DKG_ACTIVE_SESSIONS.dec();
}

/// Record DKG session abandoned
pub fn record_dkg_session_abandoned() {
    DKG_SESSIONS_TOTAL.with_label_values(&["abandoned"]).inc();
    DKG_ACTIVE_SESSIONS.dec();
    DKG_ABANDONED_SESSIONS.dec();
}

/// Record DKG phase duration
pub fn record_dkg_phase_duration(phase: &str, duration_secs: f64) {
    DKG_PHASE_DURATION_SECONDS
        .with_label_values(&[phase])
        .observe(duration_secs);
}

/// Record DKG message sent
pub fn record_dkg_message_sent(message_type: &str) {
    DKG_MESSAGES_TOTAL
        .with_label_values(&[message_type, "sent"])
        .inc();
}

/// Record DKG message received
pub fn record_dkg_message_received(message_type: &str) {
    DKG_MESSAGES_TOTAL
        .with_label_values(&[message_type, "received"])
        .inc();
}

/// Record PRE request started
pub fn record_pre_request_started() {
    PRE_REQUESTS_TOTAL.with_label_values(&["started"]).inc();
    PRE_ACTIVE_REQUESTS.inc();
}

/// Record PRE request completed
pub fn record_pre_request_completed(duration_secs: f64) {
    PRE_REQUESTS_TOTAL.with_label_values(&["completed"]).inc();
    PRE_ACTIVE_REQUESTS.dec();
    PRE_REQUEST_DURATION_SECONDS
        .with_label_values(&[])
        .observe(duration_secs);
}

/// Record PRE request failed
pub fn record_pre_request_failed() {
    PRE_REQUESTS_TOTAL.with_label_values(&["failed"]).inc();
    PRE_ACTIVE_REQUESTS.dec();
}

/// Record PRE message sent
pub fn record_pre_message_sent(message_type: &str) {
    PRE_MESSAGES_TOTAL
        .with_label_values(&[message_type, "sent"])
        .inc();
}

/// Record PRE message received
pub fn record_pre_message_received(message_type: &str) {
    PRE_MESSAGES_TOTAL
        .with_label_values(&[message_type, "received"])
        .inc();
}

/// Record Sign request started
pub fn record_sign_request_started() {
    SIGN_REQUESTS_TOTAL.with_label_values(&["started"]).inc();
    SIGN_ACTIVE_REQUESTS.inc();
}

/// Record Sign request completed
pub fn record_sign_request_completed(duration_secs: f64) {
    SIGN_REQUESTS_TOTAL.with_label_values(&["completed"]).inc();
    SIGN_ACTIVE_REQUESTS.dec();
    SIGN_REQUEST_DURATION_SECONDS
        .with_label_values(&[])
        .observe(duration_secs);
}

/// Record Sign request failed
pub fn record_sign_request_failed() {
    SIGN_REQUESTS_TOTAL.with_label_values(&["failed"]).inc();
    SIGN_ACTIVE_REQUESTS.dec();
}

/// Record Sign message sent
pub fn record_sign_message_sent(message_type: &str) {
    SIGN_MESSAGES_TOTAL
        .with_label_values(&[message_type, "sent"])
        .inc();
}

/// Record sign state abandoned (expired nonce or stale response entry)
pub fn record_sign_state_abandoned() {
    SIGN_ABANDONED_STATES.inc();
}

/// Record Sign message received
pub fn record_sign_message_received(message_type: &str) {
    SIGN_MESSAGES_TOTAL
        .with_label_values(&[message_type, "received"])
        .inc();
}

/// Record StoreSecret request completed
pub fn record_store_secret_completed(duration_secs: f64) {
    STORE_SECRET_REQUESTS_TOTAL
        .with_label_values(&["completed"])
        .inc();
    STORE_SECRET_REQUEST_DURATION_SECONDS
        .with_label_values(&[])
        .observe(duration_secs);
}

/// Record StoreSecret request failed
pub fn record_store_secret_failed() {
    STORE_SECRET_REQUESTS_TOTAL
        .with_label_values(&["failed"])
        .inc();
}

// ============================================================================
// HTTP Metrics Server
// ============================================================================

/// Handle incoming HTTP requests for metrics
async fn handle_metrics(
    _req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    let mut buffer = Vec::new();
    match encoder.encode(&metric_families, &mut buffer) {
        Ok(_) => {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .body(Full::new(Bytes::from(buffer)))
                .unwrap();
            Ok(response)
        }
        Err(e) => {
            let response = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(format!(
                    "Error encoding metrics: {}",
                    e
                ))))
                .unwrap();
            Ok(response)
        }
    }
}

/// Start the metrics HTTP server
pub async fn start_metrics_server(
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "Metrics server listening");

    // Set node_info to 1 to indicate the node is running
    NODE_INFO.set(1.0);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_metrics))
                .await
            {
                tracing::error!(error = %err, "Error serving metrics connection");
            }
        });
    }
}
