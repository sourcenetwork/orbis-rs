//! Native in-process scale test: many real orbis-node instances run a full
//! fresh-DKG ceremony, then a PRE round-trip and a SIGN ceremony, against the
//! resulting ring, in one process, over real loopback Iroh P2P, against a
//! shared in-memory [`DummyBulletin`] — no Docker, no chain. PSS refresh is
//! deliberately not covered here: it was consistently harder to get
//! reliable at scale than DKG (or a reshare would be) even after several
//! rounds of tuning, so it was dropped from this suite rather than left as a
//! flaky gate. WAN (software-shaped latency/jitter/loss, via
//! `network::ShapedNetwork`) was tried too and dropped for the same reason —
//! it was consistently the less reliable case at scale in the orbis-bench
//! in-process investigation, and never got as stable as this LAN case.
//! Uses the same `crate::harness` building blocks as orbis-bench's
//! in-process backend (`bind_addr_v4("127.0.0.1:0")` to avoid iroh
//! magicsock contention at this scale — see that module's docs), driven
//! directly here so this can run in CI without pulling in the orbis-bench
//! binary. PRE/SIGN reuse `cli_tool`'s own request-building/decrypt/verify
//! helpers (already a dev-dependency) instead of reimplementing them.
//!
//! Gated behind `scale-testing` (implies `harness`) — not part of the default
//! test run: it boots dozens of real iroh endpoints in one process, which is
//! slower and noisier than the rest of the suite.
//!
//! Run with:
//!   cargo test --features scale-testing -- --nocapture scale_testing

use crate::harness::{spawn_harness_node, HarnessNodeHandle, HarnessNodeParams};
use authn::jwt_builder::{create_authenticated_request, JwtSigner};
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, KeyDerivation, RingPayload};
use crypto::helpers::generate_keypair;
use crypto::r#trait::ThresholdSigner;
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, SignImpl};
use proto::info_service::{info_service_client::InfoServiceClient, GetRingStateRequest};
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Channel;

const POLICY_ID: &str = "orbis-node-scale-test-policy";
const CONTROLLER_KEY: &str = "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";
/// Generous headroom over the hardcoded `DKG_PREPARATION_TIMEOUT` (2 minutes)
/// so a single retried attempt still has room to finish before we time out.
const DKG_DEADLINE: Duration = Duration::from_secs(180);

/// No shaping, full-mesh committee — the harshest case for the iroh
/// contention `crate::harness` works around, sized to what's proven CI-stable.
const NETWORK_SIZE: usize = 20;
const THRESHOLD: usize = 15;
/// Away from Layer 2's 51051-51074 and orbis-bench's 61000+ harness ranges,
/// so this can run alongside either without port collisions.
const BASE_PORT: u16 = 56_000;

#[tokio::test]
#[serial_test::serial(scale_test)]
async fn test_scale_dkg_pre_sign() {
    crate::helpers::test_helpers::use_fast_test_kdf();
    let bulletin = Arc::new(DummyBulletin::default());
    let runtime_base_path = std::env::temp_dir().join("orbis-node-scale-test");
    let _ = std::fs::remove_dir_all(&runtime_base_path);
    std::fs::create_dir_all(&runtime_base_path).expect("create scale-test runtime dir");
    // A fixed base port can collide with an unrelated process, or a leftover
    // process from a killed prior run of this same test — the gRPC bind
    // failure that would cause is swallowed inside `spawn_harness_node`'s
    // detached serve task (see `connect_with_retry`'s docs below), so a
    // stale port otherwise surfaces only as a 30s connect timeout with no
    // useful diagnostic. Resolve to an actually-free block up front instead.
    let base_port = find_free_port_block(
        BASE_PORT,
        u16::try_from(NETWORK_SIZE).expect("NETWORK_SIZE fits in u16"),
    );

    let mut nodes: Vec<HarnessNodeHandle> = Vec::with_capacity(NETWORK_SIZE);
    let mut node_keys: Vec<String> = Vec::with_capacity(NETWORK_SIZE);
    for index in 1..=NETWORK_SIZE {
        let port = base_port + u16::try_from(index - 1).expect("NETWORK_SIZE fits in u16");
        let db_path = runtime_base_path.join(format!("node-{index:03}.redb"));
        let params = HarnessNodeParams {
            grpc_addr: format!("127.0.0.1:{port}"),
            db_path: db_path.to_string_lossy().into_owned(),
            password: format!("orbis-node-scale-test-{index}"),
            runtime_base_path: &runtime_base_path,
            policy_id: POLICY_ID.to_string(),
            node_controller_key: CONTROLLER_KEY.to_string(),
            network_shaping: None,
            // No PSS scheduler needed — this test only exercises DKG/PRE/SIGN.
            pss_poll_interval_secs: 0,
        };
        let handle = spawn_harness_node(params, bulletin.clone())
            .await
            .unwrap_or_else(|error| panic!("spawn scale-test node {index}: {error:#}"));
        node_keys.push(handle.node_key.clone());
        nodes.push(handle);
    }

    let ring_id = "scale-test-ring".to_string();
    let payload = RingPayload {
        ring_pk: String::new(),
        peer_node_keys: node_keys,
        threshold: THRESHOLD as u32,
        pss_interval: 86_400,
        policy_id: Some(POLICY_ID.to_string()),
        ..Default::default()
    };
    bulletin
        .set_ring(ring_id.clone(), payload)
        .expect("seed pending scale-test ring");

    let mut info_clients = Vec::with_capacity(NETWORK_SIZE);
    for node in &nodes {
        let channel = connect_with_retry(&node.grpc_endpoint, Duration::from_secs(30))
            .await
            .expect("connect info client");
        info_clients.push(InfoServiceClient::new(channel));
    }
    // All of this network's iroh endpoints just bound in quick succession;
    // give magicsock's background discovery a moment to settle before
    // StartDkg forwards to the (single, unretried) canonical leader dial —
    // without this, that first dial reliably raced discovery and failed
    // outright with "No addressing information available" (reproduced
    // consistently without this delay; every gRPC connect above already
    // retries past the equivalent race, but this one dial doesn't).
    tokio::time::sleep(Duration::from_secs(2)).await;

    let initiator_channel = connect_with_retry(&nodes[0].grpc_endpoint, Duration::from_secs(30))
        .await
        .expect("connect to DKG initiator");
    let signer = JwtSigner::new();
    let token = signer.create_dkg_jwt(&ring_id).expect("create DKG jwt");
    // The initiator forwards StartDkg to the ring's canonical leader over a
    // fresh iroh dial, with no retry of its own — unlike the later "prepare"
    // fan-out. Right after boot, iroh's magicsock discovery for a given peer
    // can still be settling, so a transient `Unavailable` here is expected
    // occasionally at this scale; retry through it rather than treating it
    // as ceremony failure (any other error is a real failure and propagates
    // immediately).
    let start_dkg_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let request = create_authenticated_request(
            StartDkgRequest {
                ring_id: ring_id.clone(),
            },
            &token,
        )
        .expect("build authenticated StartDkg request");
        match DkgServiceClient::new(initiator_channel.clone())
            .start_dkg(request)
            .await
        {
            Ok(_) => break,
            Err(status)
                if status.code() == tonic::Code::Unavailable
                    && tokio::time::Instant::now() < start_dkg_deadline =>
            {
                eprintln!("StartDkg attempt {attempt} hit transient error, retrying: {status}");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(status) => panic!("start DKG (attempt {attempt}): {status}"),
        }
    }

    let started = tokio::time::Instant::now();
    let ring_pk = tokio::time::timeout(DKG_DEADLINE, async {
        let mut last_progress = tokio::time::Instant::now();
        loop {
            if let Ok(post) = bulletin.read(ring_id.clone(), BulletinKind::Ring).await {
                if let Ok(ring) = RingPayload::try_from(post) {
                    if !ring.ring_pk.is_empty() {
                        // Finalized on the shared bulletin; cross-check every
                        // committee member's own local state has converged on
                        // it too before declaring success, the same
                        // two-phase check orbis-bench's in-process backend
                        // performs after a DKG ceremony.
                        let mut states = Vec::with_capacity(info_clients.len());
                        let mut converged = true;
                        for client in &mut info_clients {
                            let request = GetRingStateRequest {
                                ring_pk_hex: ring.ring_pk.clone(),
                            };
                            match client.get_ring_state(request).await {
                                Ok(response) => states.push(response.into_inner()),
                                Err(_) => {
                                    converged = false;
                                    break;
                                }
                            }
                        }
                        if converged {
                            let expected = states.first().map(|s| s.public_polynomial.clone());
                            if expected.as_deref().is_some_and(|p| !p.is_empty())
                                && states
                                    .iter()
                                    .all(|s| Some(&s.public_polynomial) == expected.as_ref())
                            {
                                return ring.ring_pk;
                            }
                        }
                    }
                }
            }
            if last_progress.elapsed() >= Duration::from_secs(10) {
                eprintln!(
                    "waiting for {NETWORK_SIZE}-node DKG to finalize and converge ({:?} elapsed)",
                    started.elapsed()
                );
                last_progress = tokio::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{NETWORK_SIZE}-node DKG (threshold={THRESHOLD}) did not finalize and \
             converge within {DKG_DEADLINE:?}"
        )
    });

    eprintln!(
        "{NETWORK_SIZE}-node DKG (threshold={THRESHOLD}) finalized in {:?}, ring_pk={ring_pk}",
        started.elapsed()
    );

    // Any committee member can serve PRE/SIGN requests; node 1 is arbitrary.
    let endpoint = nodes[0].grpc_endpoint.clone();
    let resource = "document";
    let permission = "read";

    // ---- PRE round-trip ----
    let reader_identity = "orbis-node-scale-test-reader".to_string();
    let (reader_sk, reader_pk) = generate_keypair().expect("generate PRE reader keypair");
    // Fully-qualified: decaf377's underlying scalar/point types have inherent
    // `to_bytes` methods that shadow `CryptoSerialize::to_bytes` (see
    // `cli_tool::do_generate_reader_key` for the same workaround).
    let reader_pk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk"));
    let reader_sk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk"));
    let plaintext = b"orbis-node scale test plaintext".to_vec();

    let prepared = cli_tool::prepare_secret(
        &plaintext,
        &ring_pk,
        None,
        POLICY_ID.to_string(),
        resource.to_string(),
        permission.to_string(),
        None,
        None,
        None,
    )
    .expect("prepare PRE secret");
    let stored = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared,
        ring_id.clone(),
        POLICY_ID.to_string(),
        resource.to_string(),
        permission.to_string(),
        Some(reader_identity.clone()),
        true,
        None,
        None,
    )
    .await
    .expect("store PRE secret");
    let decrypted = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk.clone(),
        reader_pk_hex,
        Some(reader_sk_hex),
        stored.object_id,
        Some(reader_identity),
        None,
        None,
        None,
        None,
        false,
    )
    .await
    .expect("run PRE ceremony");
    assert_eq!(
        decrypted, plaintext,
        "PRE round-trip returned the wrong plaintext"
    );
    eprintln!("PRE round-trip verified across {NETWORK_SIZE} nodes");

    // ---- SIGN ceremony ----
    let sign_identity = "orbis-node-scale-test-signer".to_string();
    let derivation = "scale-test-derivation";
    let ring_pk_point =
        GroupAffine::from_bytes(&hex::decode(&ring_pk).expect("decode ring_pk hex"))
            .expect("parse ring_pk point");
    // Mirrors `HarnessNetwork::post_key_derivation` in orbis-bench's harness:
    // derive the SIGN public key locally, then post the `KeyDerivation`
    // record straight to the shared bulletin (no chain in this backend).
    let metadata = SignImpl::encode_metadata(POLICY_ID, resource, permission);
    let derived_pk =
        SignImpl::derive_public_key(&ring_pk_point, derivation.as_bytes(), Some(&metadata))
            .expect("derive SIGN public key");
    let key_derivation = KeyDerivation {
        ring_id: ring_id.clone(),
        derivation: derivation.to_string(),
        policy_id: POLICY_ID.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
    };
    let derivation_payload = serde_json::to_vec(&key_derivation).expect("serialize KeyDerivation");
    let derivation_id = bulletin
        .post(BulletinWriteKind::KeyDerivation, derivation_payload)
        .await
        .expect("post KeyDerivation");

    let message = b"orbis-node scale test message".to_vec();
    let sign_result = cli_tool::do_sign(
        endpoint,
        message.clone(),
        derivation_id,
        Some(sign_identity),
        None,
        None,
    )
    .await
    .expect("run SIGN ceremony");
    let signature_bytes = hex::decode(&sign_result.signature).expect("decode signature hex");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes)
        .expect("parse signature");
    SignImpl::new()
        .verify(&derived_pk, &message, &signature)
        .expect("SIGN signature failed verification");
    eprintln!("SIGN ceremony verified across {NETWORK_SIZE} nodes");

    drop(nodes);
    let _ = std::fs::remove_dir_all(&runtime_base_path);
}

/// Find a contiguous block of `count` free `127.0.0.1` ports, starting the
/// search at `preferred_base` and advancing a whole block at a time on
/// conflict. Preserves the existing sequential `base + offset` per-node
/// addressing — only the chosen base changes. The bind-then-drop probe has
/// an inherent TOCTOU race against whatever binds the real listener
/// afterward; accepted as a best-effort improvement over a static port, not
/// a hard guarantee.
fn find_free_port_block(preferred_base: u16, count: u16) -> u16 {
    const MAX_BLOCKS_TRIED: u16 = 200;
    let count = count.max(1);
    'block: for block in 0..MAX_BLOCKS_TRIED {
        let Some(candidate_base) = preferred_base.checked_add(block.saturating_mul(count)) else {
            break;
        };
        for offset in 0..count {
            let Some(port) = candidate_base.checked_add(offset) else {
                continue 'block;
            };
            match std::net::TcpListener::bind(("127.0.0.1", port)) {
                Ok(listener) => drop(listener),
                Err(_) => continue 'block,
            }
        }
        return candidate_base;
    }
    panic!(
        "could not find {count} consecutive free ports starting near {preferred_base} \
         after {MAX_BLOCKS_TRIED} attempts"
    );
}

/// Retry connecting until the node's gRPC server is actually accepting
/// connections. `spawn_harness_node` returns as soon as its serve task is
/// *spawned*, not once the listener is bound — a bare `.connect()` right
/// after can race that and fail with "connection refused".
async fn connect_with_retry(grpc_url: &str, deadline: Duration) -> anyhow::Result<Channel> {
    tokio::time::timeout(deadline, async {
        loop {
            match Channel::from_shared(grpc_url.to_string())
                .expect("parse grpc endpoint")
                .connect()
                .await
            {
                Ok(channel) => return channel,
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out connecting to {grpc_url}"))
}
