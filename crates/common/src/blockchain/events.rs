//! Chain event subscription utilities.
//!
//! Provides functions for subscribing to Vera chain events via
//! CometBFT's WebSocket endpoint, replacing polling-based approaches.

use crate::blockchain::{BlockchainError, Result};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type EventStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Data extracted from a bulletin post creation event.
#[derive(Debug, Clone)]
pub struct BulletinPostEvent {
    /// The event type that matched (for debugging)
    pub event_type: String,
    pub ring_id: String,
    pub namespace: String,
    pub creator_did: String,
    pub artifact: String,
}

/// A pre-established WebSocket subscription for bulletin post events.
///
/// Create this BEFORE starting the operation that will produce the event
/// (e.g., before calling `do_dkg`), then call [`wait_for_artifact`] to
/// wait for the matching event. This avoids race conditions where the
/// event fires before the subscription is established.
///
/// # Example
/// ```ignore
/// let subscription = BulletinEventSubscription::connect("http://localhost:26657").await?;
/// let dkg_result = cli_tool::do_dkg(endpoint, threshold, peer_ids, None).await?;
/// let event = subscription.wait_for_artifact(&dkg_result.session_id, Duration::from_secs(60)).await?;
/// ```
pub struct BulletinEventSubscription {
    stream: EventStream,
}

impl BulletinEventSubscription {
    /// Connect to the CometBFT WebSocket and subscribe to all Tx events.
    ///
    /// Uses a broad `tm.event='Tx'` subscription and filters client-side,
    /// which is more robust against event type naming differences across
    /// chain versions.
    pub async fn connect(rpc_url: &str) -> Result<Self> {
        let ws_url = rpc_url_to_ws(rpc_url);

        let (mut stream, _) = connect_async(ws_url.as_str())
            .await
            .map_err(|e| BlockchainError::Rpc(format!("WebSocket connection failed: {}", e)))?;

        // Subscribe to all Tx events - we filter client-side for robustness
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "subscribe",
            "id": "orbis-bulletin-events",
            "params": { "query": "tm.event='Tx'" }
        });

        stream
            .send(Message::Text(request.to_string().into()))
            .await
            .map_err(|e| BlockchainError::Rpc(format!("Event subscription failed: {}", e)))?;

        await_subscribe_ack(&mut stream, "orbis-bulletin-events").await?;

        Ok(Self { stream })
    }

    /// Wait for a bulletin post event whose `artifact` attribute matches the given value.
    ///
    /// Scans all events in each transaction for any event type that has an `artifact`
    /// attribute matching the provided value. This is resilient to differences in the
    /// exact event type name across chain versions.
    pub async fn wait_for_artifact(
        mut self,
        artifact: &str,
        timeout: Duration,
    ) -> Result<BulletinPostEvent> {
        let result = tokio::time::timeout(timeout, self.wait_for_artifact_inner(artifact)).await;
        let _ = self.stream.close(None).await;

        result.map_err(|_| {
            BlockchainError::Timeout(format!(
                "Timed out waiting for bulletin post event with artifact '{}'",
                artifact,
            ))
        })?
    }

    async fn wait_for_artifact_inner(&mut self, artifact: &str) -> Result<BulletinPostEvent> {
        while let Some(message_result) = self.stream.next().await {
            let message = message_result
                .map_err(|e| BlockchainError::Rpc(format!("Event stream error: {}", e)))?;

            let events = match message {
                Message::Text(payload) => extract_events(payload.as_str()),
                Message::Binary(payload) => {
                    std::str::from_utf8(&payload).ok().and_then(extract_events)
                }
                Message::Close(_) => break,
                _ => None,
            };

            if let Some(post_event) = find_artifact_event(&events, artifact) {
                return Ok(post_event);
            }
        }

        Err(BlockchainError::Rpc(
            "Event subscription ended unexpectedly".to_string(),
        ))
    }
}

fn extract_events(payload: &str) -> Option<BTreeMap<String, Vec<String>>> {
    let value: Value = serde_json::from_str(payload).ok()?;

    if let Some(events) = value.pointer("/result/events").and_then(Value::as_object) {
        let mut flattened = BTreeMap::new();
        for (key, values) in events {
            let values = values
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            flattened.insert(key.clone(), values);
        }
        return Some(flattened);
    }

    let event_items = value
        .pointer("/result/data/value/TxResult/result/events")
        .and_then(Value::as_array)?;

    let mut flattened = BTreeMap::new();
    for event in event_items {
        let event_type = event.get("type").and_then(Value::as_str)?;
        let attributes = event.get("attributes").and_then(Value::as_array)?;

        for attr in attributes {
            let key = attr.get("key").and_then(Value::as_str)?;
            let value = attr
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default();
            flattened
                .entry(format!("{}.{}", event_type, key))
                .or_insert_with(Vec::new)
                .push(value.to_string());
        }
    }

    Some(flattened)
}

/// Scan the flattened event attributes map for any event with a matching `artifact`.
///
/// CometBFT delivers subscription events with a flattened `events` map where keys
/// follow the format `{event_type}.{attribute_key}`. Instead of hardcoding the event
/// type name, we scan all keys ending in `.artifact` to find a match.
fn find_artifact_event(
    events: &Option<BTreeMap<String, Vec<String>>>,
    artifact: &str,
) -> Option<BulletinPostEvent> {
    let events = events.as_ref()?;

    // Find any event type that has an artifact attribute matching our value.
    // Cosmos SDK typed events JSON-encode string attributes, wrapping them in
    // literal quotes (e.g., `"\"value\""`), so we strip those before comparing.
    for (key, values) in events {
        if !key.ends_with(".artifact") {
            continue;
        }

        if let Some(idx) = values.iter().position(|v| v.trim_matches('"') == artifact) {
            // Extract the event type prefix (everything before ".artifact")
            let event_type = key.strip_suffix(".artifact")?;

            let get_attr = |attr_key: &str| -> String {
                events
                    .get(&format!("{}.{}", event_type, attr_key))
                    .and_then(|vec| vec.get(idx))
                    .map(|v| v.trim_matches('"').to_string())
                    .unwrap_or_default()
            };

            return Some(BulletinPostEvent {
                event_type: event_type.to_string(),
                ring_id: get_attr("ring_id"),
                namespace: get_attr("namespace"),
                creator_did: get_attr("creator_did"),
                artifact: artifact.to_string(),
            });
        }
    }

    None
}

/// Data extracted from an on-chain report accepted event.
#[derive(Debug, Clone)]
pub struct ReportAcceptedEvent {
    pub report_id: String,
    pub ring_id: String,
    pub report_type: String,
    pub reporter_node_key: String,
    pub accused_node_key: String,
}

/// A pre-established WebSocket subscription for report accepted events.
///
/// Create this BEFORE the operation that will produce the event, then call
/// [`wait_for_report_accepted`] to block until the chain emits the event.
///
/// The connection is pumped by a background task from the moment [`connect`]
/// returns, not just while a `wait_for_*` call is polling it. Without this, a
/// caller that does other slow work (e.g. an operation that blocks for
/// minutes) between `connect()` and the first `wait_for_*` call leaves the
/// socket completely unread — no incoming server pings ever get answered —
/// and CometBFT's WebSocket server (or an intermediate proxy) can reset the
/// idle connection well before the caller ever starts waiting on it.
///
/// [`connect`]: Self::connect
pub struct ReportEventSubscription {
    rx: tokio::sync::mpsc::UnboundedReceiver<std::result::Result<Message, String>>,
    pump: tokio::task::JoinHandle<()>,
}

impl ReportEventSubscription {
    pub async fn connect(rpc_url: &str) -> Result<Self> {
        let ws_url = rpc_url_to_ws(rpc_url);

        let (mut stream, _) = connect_async(ws_url.as_str())
            .await
            .map_err(|e| BlockchainError::Rpc(format!("WebSocket connection failed: {}", e)))?;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "subscribe",
            "id": "orbis-report-events",
            "params": { "query": "tm.event='Tx'" }
        });

        stream
            .send(Message::Text(request.to_string().into()))
            .await
            .map_err(|e| BlockchainError::Rpc(format!("Event subscription failed: {}", e)))?;

        await_subscribe_ack(&mut stream, "orbis-report-events").await?;

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let pump = tokio::spawn(async move {
            while let Some(message_result) = stream.next().await {
                let forwarded = message_result.map_err(|e| e.to_string());
                if tx.send(forwarded).is_err() {
                    break;
                }
            }
            let _ = stream.close(None).await;
        });

        Ok(Self { rx, pump })
    }

    pub async fn wait_for_report_accepted(
        self,
        ring_id: &str,
        timeout: Duration,
    ) -> Result<ReportAcceptedEvent> {
        self.wait_for_report_accepted_matching_inner(ring_id, timeout, |_| true, false)
            .await
    }

    pub async fn wait_for_report_accepted_matching<F>(
        self,
        ring_id: &str,
        timeout: Duration,
        predicate: F,
    ) -> Result<ReportAcceptedEvent>
    where
        F: FnMut(&ReportAcceptedEvent) -> bool,
    {
        self.wait_for_report_accepted_matching_inner(ring_id, timeout, predicate, true)
            .await
    }

    async fn wait_for_report_accepted_matching_inner<F>(
        mut self,
        ring_id: &str,
        timeout: Duration,
        mut predicate: F,
        require_matching: bool,
    ) -> Result<ReportAcceptedEvent>
    where
        F: FnMut(&ReportAcceptedEvent) -> bool,
    {
        let result = tokio::time::timeout(timeout, async {
            loop {
                let event = self.wait_for_report_inner(ring_id).await?;
                if predicate(&event) {
                    return Ok(event);
                }
            }
        })
        .await;
        self.pump.abort();

        result.map_err(|_| {
            let qualifier = if require_matching { " matching" } else { "" };
            BlockchainError::Timeout(format!(
                "Timed out waiting for{} report accepted event for ring '{}'",
                qualifier, ring_id,
            ))
        })?
    }

    async fn wait_for_report_inner(&mut self, ring_id: &str) -> Result<ReportAcceptedEvent> {
        while let Some(message_result) = self.rx.recv().await {
            let message = message_result
                .map_err(|e| BlockchainError::Rpc(format!("Event stream error: {}", e)))?;

            let events = match message {
                Message::Text(payload) => extract_events(payload.as_str()),
                Message::Binary(payload) => {
                    std::str::from_utf8(&payload).ok().and_then(extract_events)
                }
                Message::Close(_) => break,
                _ => None,
            };

            if let Some(event) = find_report_accepted_event(&events, ring_id) {
                return Ok(event);
            }
        }

        Err(BlockchainError::Rpc(
            "Event subscription ended unexpectedly".to_string(),
        ))
    }
}

/// Scan the flattened event attributes map for a report accepted event matching the given ring_id.
fn find_report_accepted_event(
    events: &Option<BTreeMap<String, Vec<String>>>,
    ring_id: &str,
) -> Option<ReportAcceptedEvent> {
    let events = events.as_ref()?;

    // Scan for any event that has an accused_node_key attribute (unique to report events).
    // Cosmos SDK typed events JSON-encode string attributes, so strip literal quotes.
    for key in events.keys() {
        if !key.ends_with(".accused_node_key") {
            continue;
        }

        let event_type = key.strip_suffix(".accused_node_key")?;

        let get_first = |attr: &str| -> String {
            events
                .get(&format!("{}.{}", event_type, attr))
                .and_then(|v| v.first())
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_default()
        };

        let event_ring_id = get_first("ring_id");
        if event_ring_id != ring_id {
            continue;
        }

        return Some(ReportAcceptedEvent {
            report_id: get_first("report_id"),
            ring_id: event_ring_id,
            report_type: get_first("report_type"),
            reporter_node_key: get_first("reporter_node_key"),
            accused_node_key: get_first("accused_node_key"),
        });
    }

    None
}

/// Convert an HTTP RPC URL to a WebSocket URL.
///
/// Transforms `http://host:port` to `ws://host:port/websocket`
/// (and `https://` to `wss://`).
/// Read and validate the JSON-RPC acknowledgement that CometBFT sends after a subscribe request.
/// Returns an error if the ack is missing, unreadable, or contains a JSON-RPC error object.
async fn await_subscribe_ack(stream: &mut EventStream, id: &str) -> Result<()> {
    match stream.next().await {
        Some(Ok(Message::Text(payload))) => {
            let value: Value = serde_json::from_str(&payload).map_err(|e| {
                BlockchainError::Rpc(format!("Subscribe ack parse error (id={}): {}", id, e))
            })?;
            if let Some(err) = value.get("error") {
                return Err(BlockchainError::Rpc(format!(
                    "Event subscription rejected by server (id={}): {}",
                    id, err
                )));
            }
            Ok(())
        }
        Some(Ok(_)) => Err(BlockchainError::Rpc(format!(
            "Unexpected message type in subscribe ack (id={})",
            id
        ))),
        Some(Err(e)) => Err(BlockchainError::Rpc(format!(
            "WebSocket error reading subscribe ack (id={}): {}",
            id, e
        ))),
        None => Err(BlockchainError::Rpc(format!(
            "WebSocket closed before subscribe ack (id={})",
            id
        ))),
    }
}

fn rpc_url_to_ws(rpc_url: &str) -> String {
    let base = rpc_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    format!("{}/websocket", base)
}
