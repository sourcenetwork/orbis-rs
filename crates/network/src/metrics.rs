//! Prometheus metrics for the P2P network layer
//!
//! Provides observability into connection health, message throughput, and latencies.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec,
    HistogramVec,
};

lazy_static! {
    // Connection metrics
    pub static ref P2P_CONNECTIONS_TOTAL: CounterVec = register_counter_vec!(
        "p2p_connections_total",
        "Total number of P2P connection attempts",
        &["protocol", "status"]
    )
    .expect("failed to register p2p_connections_total");

    pub static ref P2P_ACTIVE_CONNECTIONS: GaugeVec = register_gauge_vec!(
        "p2p_active_connections",
        "Number of currently active P2P connections",
        &["protocol"]
    )
    .expect("failed to register p2p_active_connections");

    // Message metrics
    pub static ref P2P_MESSAGES_SENT_TOTAL: CounterVec = register_counter_vec!(
        "p2p_messages_sent_total",
        "Total number of P2P messages sent",
        &["protocol"]
    )
    .expect("failed to register p2p_messages_sent_total");

    pub static ref P2P_MESSAGES_RECEIVED_TOTAL: CounterVec = register_counter_vec!(
        "p2p_messages_received_total",
        "Total number of P2P messages received",
        &["protocol"]
    )
    .expect("failed to register p2p_messages_received_total");

    pub static ref P2P_BYTES_SENT_TOTAL: CounterVec = register_counter_vec!(
        "p2p_bytes_sent_total",
        "Total bytes sent over P2P",
        &["protocol"]
    )
    .expect("failed to register p2p_bytes_sent_total");

    pub static ref P2P_BYTES_RECEIVED_TOTAL: CounterVec = register_counter_vec!(
        "p2p_bytes_received_total",
        "Total bytes received over P2P",
        &["protocol"]
    )
    .expect("failed to register p2p_bytes_received_total");

    // Latency metrics (in seconds)
    pub static ref P2P_SEND_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "p2p_send_duration_seconds",
        "Time taken to send a P2P message",
        &["protocol"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .expect("failed to register p2p_send_duration_seconds");

    pub static ref P2P_RECV_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "p2p_recv_duration_seconds",
        "Time taken to receive a P2P message",
        &["protocol"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .expect("failed to register p2p_recv_duration_seconds");

    pub static ref P2P_CONNECT_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "p2p_connect_duration_seconds",
        "Time taken to establish a P2P connection",
        &["protocol"],
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("failed to register p2p_connect_duration_seconds");

    // Error metrics
    pub static ref P2P_ERRORS_TOTAL: CounterVec = register_counter_vec!(
        "p2p_errors_total",
        "Total number of P2P errors",
        &["protocol", "operation"]
    )
    .expect("failed to register p2p_errors_total");
}

/// Force initialization of all metrics. Call early in startup so any
/// duplicate-name panic crashes the process instead of silently killing a task.
pub fn init() {
    lazy_static::initialize(&P2P_CONNECTIONS_TOTAL);
    lazy_static::initialize(&P2P_ACTIVE_CONNECTIONS);
    lazy_static::initialize(&P2P_MESSAGES_SENT_TOTAL);
    lazy_static::initialize(&P2P_MESSAGES_RECEIVED_TOTAL);
    lazy_static::initialize(&P2P_BYTES_SENT_TOTAL);
    lazy_static::initialize(&P2P_BYTES_RECEIVED_TOTAL);
    lazy_static::initialize(&P2P_SEND_DURATION_SECONDS);
    lazy_static::initialize(&P2P_RECV_DURATION_SECONDS);
    lazy_static::initialize(&P2P_CONNECT_DURATION_SECONDS);
    lazy_static::initialize(&P2P_ERRORS_TOTAL);
}

/// Helper to convert protocol bytes to a string label
pub fn protocol_label(protocol: &[u8]) -> String {
    std::str::from_utf8(protocol)
        .unwrap_or("unknown")
        .to_string()
}

/// Record a successful connection
pub fn record_connection_success(protocol: &[u8], duration_secs: f64) {
    let label = protocol_label(protocol);
    P2P_CONNECTIONS_TOTAL
        .with_label_values(&[&label, "success"])
        .inc();
    P2P_ACTIVE_CONNECTIONS.with_label_values(&[&label]).inc();
    P2P_CONNECT_DURATION_SECONDS
        .with_label_values(&[&label])
        .observe(duration_secs);
}

/// Record a failed connection
pub fn record_connection_failure(protocol: &[u8]) {
    let label = protocol_label(protocol);
    P2P_CONNECTIONS_TOTAL
        .with_label_values(&[&label, "failed"])
        .inc();
    P2P_ERRORS_TOTAL
        .with_label_values(&[&label, "connect"])
        .inc();
}

/// Record connection closed
pub fn record_connection_closed(protocol: &[u8]) {
    let label = protocol_label(protocol);
    P2P_ACTIVE_CONNECTIONS.with_label_values(&[&label]).dec();
}

/// Record a message sent
pub fn record_message_sent(protocol: &[u8], bytes: usize, duration_secs: f64) {
    let label = protocol_label(protocol);
    P2P_MESSAGES_SENT_TOTAL.with_label_values(&[&label]).inc();
    P2P_BYTES_SENT_TOTAL
        .with_label_values(&[&label])
        .inc_by(bytes as f64);
    P2P_SEND_DURATION_SECONDS
        .with_label_values(&[&label])
        .observe(duration_secs);
}

/// Record a message received
pub fn record_message_received(protocol: &[u8], bytes: usize, duration_secs: f64) {
    let label = protocol_label(protocol);
    P2P_MESSAGES_RECEIVED_TOTAL
        .with_label_values(&[&label])
        .inc();
    P2P_BYTES_RECEIVED_TOTAL
        .with_label_values(&[&label])
        .inc_by(bytes as f64);
    P2P_RECV_DURATION_SECONDS
        .with_label_values(&[&label])
        .observe(duration_secs);
}

/// Record a send error
pub fn record_send_error(protocol: &[u8]) {
    let label = protocol_label(protocol);
    P2P_ERRORS_TOTAL.with_label_values(&[&label, "send"]).inc();
}

/// Record a receive error
pub fn record_recv_error(protocol: &[u8]) {
    let label = protocol_label(protocol);
    P2P_ERRORS_TOTAL.with_label_values(&[&label, "recv"]).inc();
}

/// Record an inbound stream dropped before handler execution.
pub fn record_ingress_limited(protocol: &[u8], limit: &'static str) {
    let label = protocol_label(protocol);
    P2P_ERRORS_TOTAL.with_label_values(&[&label, limit]).inc();
}
