//! DKG fixture for e2e tests.
//!
//! Running DKG is expensive (~30-40s). This module provides a helper that
//! starts a 3-node ring, runs DKG, and returns the results.
//!
//! The returned `DkgFixture` owns the ring, SourceHub, and run directory
//! independently. Drop order is: ring -> sourcehub -> run_dir (by field order).
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

use crate::orbis::{OrbisRing, SourceHubUrls};
use crate::sourcehub::{self, SourceHubNode};
use crate::{generate_identity_keys, generate_run_id, TestRunDir};

/// The bulletin namespace used for ring payloads (must match orbis-node constant).
const BULLETIN_RING_NAMESPACE: &str = "orbis";

/// Results of a completed DKG ceremony, ready for use by tests.
///
/// Field drop order: ring (orbis nodes killed first) -> sourcehub -> run_dir (cleaned last).
pub struct DkgFixture {
    /// The running ring (orbis-node processes). Killed on drop.
    pub ring: OrbisRing,
    /// The running SourceHub devnet. Killed on drop (after ring).
    pub sourcehub: SourceHubNode,
    /// Hex-encoded collective public key from DKG.
    pub ring_pk_hex: String,
    /// Ring ID (bulletin post ID of the ring payload).
    pub ring_id: String,
    /// Node info for each node (public_address, peer_id, p2p_address).
    pub node_infos: Vec<cli_tool::NodeInfoResult>,
    /// Test run directory. Cleaned up last on drop (unless ORBIS_E2E_KEEP=1).
    _run_dir: TestRunDir,
}

impl DkgFixture {
    /// Get the chain config pointing at this fixture's SourceHub.
    pub fn chain_config(&self) -> ChainConfig {
        self.sourcehub.chain_config()
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

    let run_id = generate_run_id();
    let run_dir = TestRunDir::new(&run_id).expect("fixture: create run dir");
    let identity_keys = generate_identity_keys(&run_id, 3);

    // Start SourceHub
    let sh_ports =
        sourcehub::allocate_source_hub_ports().expect("fixture: allocate sourcehub ports");
    let sh_home = run_dir
        .component_dir("sourcehub")
        .expect("fixture: create sourcehub dir");
    let sh_log_dir = sh_home.join("logs");
    std::fs::create_dir_all(&sh_log_dir).expect("fixture: create sourcehub log dir");

    let sourcehub = SourceHubNode::start(
        sh_home,
        sh_log_dir,
        &sh_ports,
        &identity_keys,
        Duration::from_secs(60),
    )
    .await
    .expect("fixture: sourcehub should start");

    // Build the ring
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .base_dir(run_dir.path())
        .identity_keys(identity_keys)
        .sourcehub_urls(SourceHubUrls::from(&sourcehub))
        .build()
        .await
        .expect("fixture: ring should start");

    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("fixture: all nodes should be healthy");

    let chain_config = sourcehub.chain_config();

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
        sourcehub,
        ring_pk_hex,
        ring_id,
        node_infos,
        _run_dir: run_dir,
    }
}
