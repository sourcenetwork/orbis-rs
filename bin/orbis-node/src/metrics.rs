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
    register_counter, register_counter_vec, register_gauge, register_gauge_vec,
    register_histogram_vec, Counter, CounterVec, Encoder, Gauge, GaugeVec, HistogramVec,
    TextEncoder,
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
        &["kind", "phase"],
        vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 900.0]
    )
    .expect("failed to register dkg_phase_duration_seconds");

    pub static ref DKG_SESSION_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "dkg_session_duration_seconds",
        "End-to-end duration of DKG-backed ceremonies",
        &["kind", "outcome"],
        vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 900.0]
    )
    .expect("failed to register dkg_session_duration_seconds");

    pub static ref PSS_SCHEDULER_DELAY_SECONDS: HistogramVec = register_histogram_vec!(
        "pss_scheduler_delay_seconds",
        "Delay between a refresh becoming due and a scheduler observing it",
        &[],
        vec![0.0, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
    )
    .expect("failed to register pss_scheduler_delay_seconds");

    pub static ref DKG_TRANSPORT_MESSAGES_TOTAL: CounterVec = register_counter_vec!(
        "dkg_transport_messages_total",
        "Total number of typed DKG transport messages",
        &["plane", "message", "direction"]
    )
    .expect("failed to register dkg_transport_messages_total");

    pub static ref DKG_ABANDONED_SESSIONS_TOTAL: Counter = register_counter!(
        "dkg_abandoned_sessions_total",
        "Total number of DKG sessions abandoned"
    )
    .expect("failed to register dkg_abandoned_sessions");

    pub static ref DKG_TRANSPORT_EVENTS_TOTAL: CounterVec = register_counter_vec!(
        "dkg_transport_events_total",
        "Bounded-cardinality events emitted by the DKG transport",
        &["plane", "event"]
    )
    .expect("failed to register dkg_transport_events_total");

    pub static ref PSS_OFFLINE_OBSERVATIONS_TOTAL: CounterVec = register_counter_vec!(
        "pss_offline_observations_total",
        "Terminal PSS peer-liveness observations by bounded transport stage and outcome",
        &["stage", "outcome"]
    )
    .expect("failed to register pss_offline_observations_total");

    pub static ref DKG_CONTROL_READINESS_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "dkg_control_readiness_duration_seconds",
        "Time from canonical leader preparation start through all-member Begin acknowledgement",
        &["kind"],
        vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0]
    )
    .expect("failed to register dkg_control_readiness_duration_seconds");

    pub static ref DKG_PRIVATE_PAIR_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "dkg_private_pair_duration_seconds",
        "Duration of an acknowledged bidirectional private pair exchange",
        &["outcome"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
    )
    .expect("failed to register dkg_private_pair_duration_seconds");

    pub static ref DKG_PUBLIC_TRANSPORT_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "dkg_public_transport_duration_seconds",
        "Public DKG contribution collection and canonical batch dissemination duration",
        &["phase", "stage"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 900.0]
    )
    .expect("failed to register dkg_public_transport_duration_seconds");

    pub static ref DKG_PRIVATE_ACTIVE_EXCHANGES: Gauge = register_gauge!(
        "dkg_private_active_exchanges",
        "Number of active inbound and outbound private pair exchanges"
    )
    .expect("failed to register dkg_private_active_exchanges");

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
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0]
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
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0]
    )
    .expect("failed to register sign_request_duration_seconds");

    pub static ref SIGN_MESSAGES_TOTAL: CounterVec = register_counter_vec!(
        "sign_messages_total",
        "Total number of signing protocol messages",
        &["message_type", "direction"]
    )
    .expect("failed to register sign_messages_total");

    pub static ref SIGN_ABANDONED_STATES_TOTAL: Counter = register_counter!(
        "sign_abandoned_states_total",
        "Total number of sign states abandoned (expired nonces or stale responses)"
    )
    .expect("failed to register sign_abandoned_states");

    // ============================================================================
    // MPC Fault Reporting Metrics
    // ============================================================================

    pub static ref REPORT_ATTEMPTS_TOTAL: CounterVec = register_counter_vec!(
        "report_attempts_total",
        "Total number of MPC fault report attempts",
        &["report_type", "status"]
    )
    .expect("failed to register report_attempts_total");

    pub static ref REPORT_HEALTH_CHECKS_TOTAL: CounterVec = register_counter_vec!(
        "report_health_checks_total",
        "Total number of independent report health-check outcomes",
        &["status"]
    )
    .expect("failed to register report_health_checks_total");

    pub static ref REPORT_IN_FLIGHT: Gauge = register_gauge!(
        "report_in_flight",
        "Number of MPC fault report workflows currently in flight"
    )
    .expect("failed to register report_in_flight");

    // ============================================================================
    // Reshare Protocol Metrics
    // ============================================================================

    pub static ref RESHARE_SESSIONS_TOTAL: CounterVec = register_counter_vec!(
        "reshare_sessions_total",
        "Total number of reshare sessions",
        &["status"]
    )
    .expect("failed to register reshare_sessions_total");

    pub static ref RESHARE_ACTIVE_SESSIONS: Gauge = register_gauge!(
        "reshare_active_sessions",
        "Number of currently active reshare sessions"
    )
    .expect("failed to register reshare_active_sessions");

    /// A reshare the chain confirmed still counts as a "completed" session (the
    /// ceremony itself succeeded), but this counts the narrower, operator-actionable
    /// failure of the local promotion write afterward — the node is left
    /// locally-stale relative to the chain-recognized committee.
    pub static ref RESHARE_PROMOTION_WRITE_FAILURES_TOTAL: Counter = register_counter!(
        "reshare_promotion_write_failures_total",
        "Total number of chain-confirmed reshares whose local bundle promotion write failed"
    )
    .expect("failed to register reshare_promotion_write_failures_total");

    // ============================================================================
    // Refresh Protocol Metrics
    // ============================================================================

    pub static ref REFRESH_SESSIONS_TOTAL: CounterVec = register_counter_vec!(
        "refresh_sessions_total",
        "Total number of refresh (PSS) sessions",
        &["status"]
    )
    .expect("failed to register refresh_sessions_total");

    pub static ref REFRESH_ACTIVE_SESSIONS: Gauge = register_gauge!(
        "refresh_active_sessions",
        "Number of currently active refresh sessions"
    )
    .expect("failed to register refresh_active_sessions");

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
    // Authentication Metrics
    // ============================================================================

    pub static ref JWT_REPLAY_REJECTED_TOTAL: CounterVec = register_counter_vec!(
        "jwt_replay_rejected_total",
        "Total number of requests rejected because their JWT id was already used or missing",
        &["reason", "site"]
    )
    .expect("failed to register jwt_replay_rejected_total");

    // ============================================================================
    // Build Info Metric
    // ============================================================================

    pub static ref ORBIS_BUILD_INFO: GaugeVec = register_gauge_vec!(
        "orbis_build_info",
        "Implementation info for this node (always 1); use labels to identify feature variants",
        &["pre_impl", "sign_impl", "local_storage_impl", "authz_impl", "bulletin_impl", "network_impl"]
    )
    .expect("failed to register orbis_build_info");
}

/// Force initialization of all metrics. Call early in startup so any
/// duplicate-name panic crashes the process instead of silently killing a task.
pub fn init() {
    lazy_static::initialize(&GRPC_REQUESTS_TOTAL);
    lazy_static::initialize(&GRPC_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&DKG_SESSIONS_TOTAL);
    lazy_static::initialize(&DKG_ACTIVE_SESSIONS);
    lazy_static::initialize(&DKG_PHASE_DURATION_SECONDS);
    lazy_static::initialize(&DKG_SESSION_DURATION_SECONDS);
    lazy_static::initialize(&PSS_SCHEDULER_DELAY_SECONDS);
    lazy_static::initialize(&DKG_TRANSPORT_MESSAGES_TOTAL);
    lazy_static::initialize(&DKG_ABANDONED_SESSIONS_TOTAL);
    lazy_static::initialize(&DKG_TRANSPORT_EVENTS_TOTAL);
    lazy_static::initialize(&PSS_OFFLINE_OBSERVATIONS_TOTAL);
    lazy_static::initialize(&DKG_CONTROL_READINESS_DURATION_SECONDS);
    lazy_static::initialize(&DKG_PRIVATE_PAIR_DURATION_SECONDS);
    lazy_static::initialize(&DKG_PUBLIC_TRANSPORT_DURATION_SECONDS);
    lazy_static::initialize(&DKG_PRIVATE_ACTIVE_EXCHANGES);
    lazy_static::initialize(&PRE_REQUESTS_TOTAL);
    lazy_static::initialize(&PRE_ACTIVE_REQUESTS);
    lazy_static::initialize(&PRE_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&PRE_MESSAGES_TOTAL);
    lazy_static::initialize(&SIGN_REQUESTS_TOTAL);
    lazy_static::initialize(&SIGN_ACTIVE_REQUESTS);
    lazy_static::initialize(&SIGN_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&SIGN_MESSAGES_TOTAL);
    lazy_static::initialize(&SIGN_ABANDONED_STATES_TOTAL);
    lazy_static::initialize(&REPORT_ATTEMPTS_TOTAL);
    lazy_static::initialize(&REPORT_HEALTH_CHECKS_TOTAL);
    lazy_static::initialize(&REPORT_IN_FLIGHT);
    lazy_static::initialize(&RESHARE_SESSIONS_TOTAL);
    lazy_static::initialize(&RESHARE_ACTIVE_SESSIONS);
    lazy_static::initialize(&REFRESH_SESSIONS_TOTAL);
    lazy_static::initialize(&REFRESH_ACTIVE_SESSIONS);
    lazy_static::initialize(&STORE_SECRET_REQUESTS_TOTAL);
    lazy_static::initialize(&STORE_SECRET_REQUEST_DURATION_SECONDS);
    lazy_static::initialize(&JWT_REPLAY_REJECTED_TOTAL);
    lazy_static::initialize(&ORBIS_BUILD_INFO);
}

// ============================================================================
// Helper functions for recording metrics
// ============================================================================

/// Records one gRPC request exactly once, including early-return error paths.
pub struct GrpcRequestGuard {
    service: &'static str,
    method: &'static str,
    start: Instant,
    finished: bool,
}

impl GrpcRequestGuard {
    pub fn new(service: &'static str, method: &'static str) -> Self {
        Self {
            service,
            method,
            start: Instant::now(),
            finished: false,
        }
    }

    pub fn success(mut self) {
        record_grpc_request(
            self.service,
            self.method,
            "ok",
            self.start.elapsed().as_secs_f64(),
        );
        self.finished = true;
    }
}

impl Drop for GrpcRequestGuard {
    fn drop(&mut self) {
        if !self.finished {
            record_grpc_request(
                self.service,
                self.method,
                "error",
                self.start.elapsed().as_secs_f64(),
            );
        }
    }
}

/// Owns the active-request gauge for a service request.
///
/// Dropping without `complete` records a failure, so cancellation and every
/// early-return path balance the gauge exactly once.
pub struct RequestMetricsGuard {
    total: &'static CounterVec,
    active: Option<&'static Gauge>,
    duration: &'static HistogramVec,
    start: Instant,
    finished: bool,
}

impl RequestMetricsGuard {
    fn new(
        total: &'static CounterVec,
        active: Option<&'static Gauge>,
        duration: &'static HistogramVec,
    ) -> Self {
        total.with_label_values(&["started"]).inc();
        if let Some(active) = active {
            active.inc();
        }
        Self {
            total,
            active,
            duration,
            start: Instant::now(),
            finished: false,
        }
    }

    pub fn complete(mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        self.total.with_label_values(&["completed"]).inc();
        if let Some(active) = self.active {
            active.dec();
        }
        self.duration.with_label_values(&[]).observe(duration);
        self.finished = true;
    }
}

impl Drop for RequestMetricsGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.total.with_label_values(&["failed"]).inc();
        if let Some(active) = self.active {
            active.dec();
        }
    }
}

pub fn track_pre_request() -> RequestMetricsGuard {
    RequestMetricsGuard::new(
        &PRE_REQUESTS_TOTAL,
        Some(&PRE_ACTIVE_REQUESTS),
        &PRE_REQUEST_DURATION_SECONDS,
    )
}

pub fn track_sign_request() -> RequestMetricsGuard {
    RequestMetricsGuard::new(
        &SIGN_REQUESTS_TOTAL,
        Some(&SIGN_ACTIVE_REQUESTS),
        &SIGN_REQUEST_DURATION_SECONDS,
    )
}

pub fn track_store_secret_request() -> RequestMetricsGuard {
    RequestMetricsGuard::new(
        &STORE_SECRET_REQUESTS_TOTAL,
        None,
        &STORE_SECRET_REQUEST_DURATION_SECONDS,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgCeremonyKind {
    Fresh,
    Refresh,
    Reshare,
}

impl DkgCeremonyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Refresh => "refresh",
            Self::Reshare => "reshare",
        }
    }
}

/// Owns all active-session gauges for one DKG-backed ceremony.
pub struct DkgSessionMetricsGuard {
    kind: DkgCeremonyKind,
    start: Instant,
    finished: bool,
}

impl DkgSessionMetricsGuard {
    pub fn new(kind: DkgCeremonyKind) -> Self {
        record_dkg_session_started();
        match kind {
            DkgCeremonyKind::Fresh => {}
            DkgCeremonyKind::Refresh => record_refresh_session_started(),
            DkgCeremonyKind::Reshare => record_reshare_session_started(),
        }
        Self {
            kind,
            start: Instant::now(),
            finished: false,
        }
    }

    pub fn complete(mut self) {
        record_dkg_session_duration(self.kind, "completed", self.start.elapsed().as_secs_f64());
        record_dkg_session_completed();
        match self.kind {
            DkgCeremonyKind::Fresh => {}
            DkgCeremonyKind::Refresh => record_refresh_session_completed(),
            DkgCeremonyKind::Reshare => record_reshare_session_completed(),
        }
        self.finished = true;
    }

    pub fn abandon(mut self) {
        record_dkg_session_duration(self.kind, "abandoned", self.start.elapsed().as_secs_f64());
        record_dkg_session_abandoned();
        match self.kind {
            DkgCeremonyKind::Fresh => {}
            DkgCeremonyKind::Refresh => record_refresh_session_failed(),
            DkgCeremonyKind::Reshare => record_reshare_session_failed(),
        }
        self.finished = true;
    }
}

impl Drop for DkgSessionMetricsGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        record_dkg_session_duration(self.kind, "failed", self.start.elapsed().as_secs_f64());
        record_dkg_session_failed();
        match self.kind {
            DkgCeremonyKind::Fresh => {}
            DkgCeremonyKind::Refresh => record_refresh_session_failed(),
            DkgCeremonyKind::Reshare => record_reshare_session_failed(),
        }
    }
}

pub fn record_dkg_phase_duration(kind: DkgCeremonyKind, phase: &str, duration_secs: f64) {
    DKG_PHASE_DURATION_SECONDS
        .with_label_values(&[kind.as_str(), phase])
        .observe(duration_secs);
}

pub fn record_dkg_session_duration(kind: DkgCeremonyKind, outcome: &str, duration_secs: f64) {
    DKG_SESSION_DURATION_SECONDS
        .with_label_values(&[kind.as_str(), outcome])
        .observe(duration_secs);
}

pub fn record_pss_scheduler_delay(duration_secs: f64) {
    PSS_SCHEDULER_DELAY_SECONDS
        .with_label_values(&[])
        .observe(duration_secs);
}

pub fn record_dkg_transport_event(plane: &str, event: &str) {
    DKG_TRANSPORT_EVENTS_TOTAL
        .with_label_values(&[plane, event])
        .inc();
}

pub fn record_pss_offline_observation(stage: &str, outcome: &str) {
    PSS_OFFLINE_OBSERVATIONS_TOTAL
        .with_label_values(&[stage, outcome])
        .inc();
}

pub fn record_dkg_control_readiness(kind: DkgCeremonyKind, duration_secs: f64) {
    DKG_CONTROL_READINESS_DURATION_SECONDS
        .with_label_values(&[kind.as_str()])
        .observe(duration_secs);
}

pub fn record_dkg_public_transport(phase: &str, stage: &str, duration_secs: f64) {
    DKG_PUBLIC_TRANSPORT_DURATION_SECONDS
        .with_label_values(&[phase, stage])
        .observe(duration_secs);
}

pub struct PrivatePairMetricsGuard {
    start: Instant,
    finished: bool,
}

impl PrivatePairMetricsGuard {
    pub fn new() -> Self {
        DKG_PRIVATE_ACTIVE_EXCHANGES.inc();
        Self {
            start: Instant::now(),
            finished: false,
        }
    }

    pub fn complete(mut self) {
        DKG_PRIVATE_PAIR_DURATION_SECONDS
            .with_label_values(&["completed"])
            .observe(self.start.elapsed().as_secs_f64());
        DKG_PRIVATE_ACTIVE_EXCHANGES.dec();
        self.finished = true;
    }
}

impl Drop for PrivatePairMetricsGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        DKG_PRIVATE_PAIR_DURATION_SECONDS
            .with_label_values(&["failed"])
            .observe(self.start.elapsed().as_secs_f64());
        DKG_PRIVATE_ACTIVE_EXCHANGES.dec();
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
    DKG_ABANDONED_SESSIONS_TOTAL.inc();
}

pub fn record_dkg_transport_message(plane: &str, message: &str, direction: &str) {
    DKG_TRANSPORT_MESSAGES_TOTAL
        .with_label_values(&[plane, message, direction])
        .inc();
}

/// Record sign state abandoned (expired nonce or stale response entry)
pub fn record_sign_state_abandoned() {
    SIGN_ABANDONED_STATES_TOTAL.inc();
}

/// One request rejected by the JWT single-use guard. `reason` is `already_used`
/// or `missing_jti`; `site` names the entry point (e.g. `start_pre`,
/// `sign_nonce_request`).
pub fn record_jwt_replay_rejected(reason: &str, site: &str) {
    JWT_REPLAY_REJECTED_TOTAL
        .with_label_values(&[reason, site])
        .inc();
}

/// Record Reshare session started
pub fn record_reshare_session_started() {
    RESHARE_SESSIONS_TOTAL.with_label_values(&["started"]).inc();
    RESHARE_ACTIVE_SESSIONS.inc();
}

/// Record Reshare session completed
pub fn record_reshare_session_completed() {
    RESHARE_SESSIONS_TOTAL
        .with_label_values(&["completed"])
        .inc();
    RESHARE_ACTIVE_SESSIONS.dec();
}

/// Record Reshare session failed
pub fn record_reshare_session_failed() {
    RESHARE_SESSIONS_TOTAL.with_label_values(&["failed"]).inc();
    RESHARE_ACTIVE_SESSIONS.dec();
}

/// Record a chain-confirmed reshare whose local bundle promotion write failed.
pub fn record_reshare_promotion_write_failure() {
    RESHARE_PROMOTION_WRITE_FAILURES_TOTAL.inc();
}

/// Record Refresh session started
pub fn record_refresh_session_started() {
    REFRESH_SESSIONS_TOTAL.with_label_values(&["started"]).inc();
    REFRESH_ACTIVE_SESSIONS.inc();
}

/// Record Refresh session completed
pub fn record_refresh_session_completed() {
    REFRESH_SESSIONS_TOTAL
        .with_label_values(&["completed"])
        .inc();
    REFRESH_ACTIVE_SESSIONS.dec();
}

/// Record Refresh session failed
pub fn record_refresh_session_failed() {
    REFRESH_SESSIONS_TOTAL.with_label_values(&["failed"]).inc();
    REFRESH_ACTIVE_SESSIONS.dec();
}

/// Set the build-info gauge. Call once at startup after `init()`.
pub fn record_build_info(
    pre_impl: &str,
    sign_impl: &str,
    local_storage_impl: &str,
    authz_impl: &str,
    bulletin_impl: &str,
    network_impl: &str,
) {
    ORBIS_BUILD_INFO
        .with_label_values(&[
            pre_impl,
            sign_impl,
            local_storage_impl,
            authz_impl,
            bulletin_impl,
            network_impl,
        ])
        .set(1.0);
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
                .expect("BUG: static metrics response builder should never fail");
            Ok(response)
        }
        Err(e) => {
            let response = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(format!(
                    "Error encoding metrics: {}",
                    e
                ))))
                .expect("BUG: static error response builder should never fail");
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

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(io, service_fn(handle_metrics))
                .await
                .inspect_err(|error| {
                    tracing::error!(error = %error, "Error serving metrics connection");
                });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{HistogramOpts, Opts};
    use std::sync::Mutex;

    static DKG_METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn request_metrics() -> (&'static CounterVec, &'static Gauge, &'static HistogramVec) {
        let total = Box::leak(Box::new(
            CounterVec::new(Opts::new("test_requests_total", "test"), &["status"])
                .expect("counter"),
        ));
        let active = Box::leak(Box::new(
            Gauge::new("test_active_requests", "test").expect("gauge"),
        ));
        let duration = Box::leak(Box::new(
            HistogramVec::new(
                HistogramOpts::new("test_request_duration_seconds", "test"),
                &[],
            )
            .expect("histogram"),
        ));
        (total, active, duration)
    }

    #[test]
    fn request_guard_balances_active_gauge_on_failure() {
        let (total, active, duration) = request_metrics();
        let baseline = active.get();
        {
            let _guard = RequestMetricsGuard::new(total, Some(active), duration);
            assert_eq!(active.get(), baseline + 1.0);
        }
        assert_eq!(active.get(), baseline);
        assert_eq!(total.with_label_values(&["failed"]).get(), 1.0);
    }

    #[test]
    fn request_guard_balances_active_gauge_on_success() {
        let (total, active, duration) = request_metrics();
        let baseline = active.get();
        RequestMetricsGuard::new(total, Some(active), duration).complete();
        assert_eq!(active.get(), baseline);
        assert_eq!(total.with_label_values(&["completed"]).get(), 1.0);
        assert_eq!(total.with_label_values(&["failed"]).get(), 0.0);
    }

    #[test]
    fn dkg_guard_observes_one_outcome_and_balances_gauges() {
        let _lock = DKG_METRICS_TEST_LOCK.lock().unwrap();
        let histogram = DKG_SESSION_DURATION_SECONDS.with_label_values(&["fresh", "completed"]);
        let count_before = histogram.get_sample_count();
        let active_before = DKG_ACTIVE_SESSIONS.get();
        DkgSessionMetricsGuard::new(DkgCeremonyKind::Fresh).complete();
        assert_eq!(DKG_ACTIVE_SESSIONS.get(), active_before);
        assert_eq!(histogram.get_sample_count(), count_before + 1);
    }

    #[test]
    fn private_pair_guard_balances_active_gauge_for_success_and_failure() {
        let _lock = DKG_METRICS_TEST_LOCK.lock().unwrap();
        let baseline = DKG_PRIVATE_ACTIVE_EXCHANGES.get();
        let failed = DKG_PRIVATE_PAIR_DURATION_SECONDS.with_label_values(&["failed"]);
        let failed_before = failed.get_sample_count();
        {
            let _guard = PrivatePairMetricsGuard::new();
            assert_eq!(DKG_PRIVATE_ACTIVE_EXCHANGES.get(), baseline + 1.0);
        }
        assert_eq!(DKG_PRIVATE_ACTIVE_EXCHANGES.get(), baseline);
        assert_eq!(failed.get_sample_count(), failed_before + 1);

        let completed = DKG_PRIVATE_PAIR_DURATION_SECONDS.with_label_values(&["completed"]);
        let completed_before = completed.get_sample_count();
        PrivatePairMetricsGuard::new().complete();
        assert_eq!(DKG_PRIVATE_ACTIVE_EXCHANGES.get(), baseline);
        assert_eq!(completed.get_sample_count(), completed_before + 1);
    }
}
