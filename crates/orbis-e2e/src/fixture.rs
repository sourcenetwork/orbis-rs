//! DKG fixture for e2e tests.
//!
//! Running DKG is expensive (~30-40s). This module provides a helper that
//! starts a 3-node ring, runs DKG, and returns the results.
//!
//! The returned `DkgFixture` owns the `OrbisRing` — when it's dropped, all
//! managed processes (orbis-node, sourcehubd) are killed via SIGTERM/SIGKILL.
//!
//! # Usage
//!
//! ```ignore
//! use orbis_e2e::fixture::setup_dkg;
//!
//! #[tokio::test]
//! async fn test_pipeline() {
//!     let fixture = setup_dkg().await;
//!     // Use fixture.ring, fixture.ring_pk_hex, fixture.chain_config(), etc.
//!     // Processes are cleaned up when `fixture` is dropped.
//! }
//! ```

use common::blockchain::events::BulletinEventSubscription;
use common::blockchain::ChainConfig;
use std::time::Duration;

use crate::orbis::OrbisRing;

/// The bulletin namespace used for ring payloads (must match orbis-node constant).
const BULLETIN_RING_NAMESPACE: &str = "orbis";

/// Results of a completed DKG ceremony, ready for use by tests.
///
/// Owns the `OrbisRing` — dropping this struct kills all managed processes.
pub struct DkgFixture {
    /// The running ring (3 nodes + SourceHub). Processes are killed on drop.
    pub ring: OrbisRing,
    /// Hex-encoded collective public key from DKG.
    pub ring_pk_hex: String,
    /// Ring ID (bulletin post ID of the ring payload).
    pub ring_id: String,
    /// Node info for each node (public_address, peer_id, p2p_address).
    pub node_infos: Vec<cli_tool::NodeInfoResult>,
}

impl DkgFixture {
    /// Get the chain config pointing at this fixture's SourceHub.
    pub fn chain_config(&self) -> ChainConfig {
        self.ring.chain_config()
    }

    /// Get the gRPC endpoint of node 0 (convenience).
    pub fn endpoint(&self) -> String {
        self.ring.node(0).grpc_addr()
    }
}

/// Start a 3-node ring with SourceHub, run DKG, and return the fixture.
///
/// This takes ~30-40s. The returned fixture owns all processes — they are
/// killed when the fixture is dropped.
pub async fn setup_dkg() -> DkgFixture {
    eprintln!("[fixture] Starting DKG fixture (3 nodes + SourceHub)...");

    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .with_sourcehub()
        .build()
        .await
        .expect("fixture: ring should start");

    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("fixture: all nodes should be healthy");

    let chain_config = ring.chain_config();
    let sourcehub = ring.sourcehub().expect("fixture: sourcehub should be running");

    // Query node info
    let mut node_infos = Vec::with_capacity(ring.node_count());
    for i in 0..ring.node_count() {
        let info = cli_tool::query_node_info(ring.node(i).grpc_addr())
            .await
            .unwrap_or_else(|e| panic!("fixture: query node{} info: {}", i, e));
        node_infos.push(info);
    }

    // Register ring namespace + add all nodes as collaborators
    cli_tool::register_bulletin_namespace(
        BULLETIN_RING_NAMESPACE.to_string(),
        chain_config.clone(),
    )
    .await
    .expect("fixture: register ring namespace");

    for info in &node_infos {
        cli_tool::add_bulletin_collaborator(
            BULLETIN_RING_NAMESPACE.to_string(),
            info.public_address.clone(),
            chain_config.clone(),
        )
        .await
        .expect("fixture: add collaborator");
    }

    // Subscribe to events BEFORE starting DKG
    let event_subscription =
        BulletinEventSubscription::connect(&sourcehub.comet_rpc_url)
            .await
            .expect("fixture: event subscription");

    // Collect peer addresses
    let peer_ids: Vec<String> = node_infos.iter().map(|n| n.p2p_address.clone()).collect();

    // Run DKG
    eprintln!("[fixture] Running DKG...");
    let dkg_result = cli_tool::do_dkg(ring.node(0).grpc_addr(), ring.threshold(), peer_ids)
        .await
        .expect("fixture: DKG should succeed");

    let session_id = dkg_result.session_id;
    let post_event = event_subscription
        .wait_for_artifact(&session_id, Duration::from_secs(120))
        .await
        .expect("fixture: DKG completion event");

    // Read ring payload
    let post_payload = cli_tool::read_bulletin_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        post_event.post_id.clone(),
        chain_config.clone(),
    )
    .await
    .expect("fixture: read ring post");

    let ring_payload: bulletin::r#trait::RingPayload =
        serde_json::from_slice(&post_payload).expect("fixture: parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk;
    let ring_id = post_event.post_id;

    eprintln!(
        "[fixture] DKG complete. Ring PK: {}..., Ring ID: {}",
        &ring_pk_hex[..40.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    DkgFixture {
        ring,
        ring_pk_hex,
        ring_id,
        node_infos,
    }
}
