//! In-process DKG execution backend: real `orbis-node` instances running as
//! tokio tasks in this process, talking real Iroh P2P over loopback, backed
//! by a shared in-memory [`DummyBulletin`] instead of a Dockerized SourceHub.
//!
//! No Docker, no blockchain, no external network dependency — this exists to
//! measure orbis's own DKG/PRE/SIGN protocol and P2P networking behavior
//! without infrastructure flakiness (SourceHub RPC hiccups, Iroh relay
//! reachability, Docker host contention) obscuring the result. See
//! `runner.rs`'s `run_stack_in_process` for the trial loops that drive this
//! network; the results/report/manifest pipeline (`results.rs`/`report.rs`)
//! is unchanged and shared with the Docker backend.
//!
//! WAN profiles (`delay_ms`/`jitter_ms`/`loss_percent`) are approximated in
//! software via `network::ShapedNetwork` instead of the Docker backend's
//! per-container `tc netem` — there's no network namespace here to shape.
//! See that module's docs for exactly what's approximated (loss is a hard
//! per-message failure, not transparent QUIC-level retransmission).
//!
//! PRE/SIGN need no chain-side ACP setup here (unlike the Docker backend's
//! `register_object_to_chain_with_config`/`set_relationship_on_chain_with_config`):
//! `DummyAuthZ` authorizes unconditionally, so orbis-node's `authz.check(...)`
//! calls (`pre/v0/helpers.rs::check_policy_access`, `sign/v0/helpers.rs`)
//! always pass regardless of what policy/resource/relationship values are
//! used, as long as they're consistent between fixture creation and the
//! PRE/SIGN request. The only real setup PRE/SIGN need is a finalized ring, a
//! stored `Document` (via `StoreSecretService`, node-local — no chain), and
//! for SIGN, a `KeyDerivation` record — the latter posted directly to the
//! shared bulletin by [`HarnessNetwork::post_key_derivation`] below, since
//! `cli_tool::post_key_derivation_with_config` unconditionally builds a real
//! `SourceHubBulletin` client and can't be reused here.

use crate::protocol::{DirectClients, NodeEndpoint};
use anyhow::{Context, Result};
use bulletin::dummy::DummyBulletin;
use bulletin::error::BulletinError;
use bulletin::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, KeyDerivation, RingPayload};
use crypto::r#trait::ThresholdSigner;
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, SignImpl};
use network::NetworkShapingProfile;
use orbis_node::harness::{spawn_harness_node, HarnessNodeHandle, HarnessNodeParams};
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::Duration;
use tokio::time::sleep;

static INIT_TRACING: Once = Once::new();

/// Install a `tracing` subscriber for harness node logs, controlled by
/// `RUST_LOG` (defaults to `warn` if unset). Safe to call from every
/// `spin_up` — only the first call takes effect. Off by default in effect
/// (warn-only) so normal runs stay quiet; set `RUST_LOG=orbis_node=debug` (or
/// similar) to see per-node DKG/network tracing during an in-process run.
fn init_tracing_once() {
    INIT_TRACING.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    });
}

/// ACP policy id every harness node whitelists on boot and every
/// harness-seeded ring/document/key-derivation references. There's no real
/// ACP/chain in this backend — `DummyAuthZ` always authorizes — but
/// orbis-node's DKG code independently checks that a ring's `policy_id`
/// appears in the participant's `NodeInfo.whitelisted_policy_ids`
/// (`dkg/v0/helpers.rs`), so this only needs to be one stable, matching
/// value shared by every harness node, ring, document, and key derivation.
pub(crate) const HARNESS_POLICY_ID: &str = "orbis-bench-harness-policy";
/// Controller key every harness node accepts as authorized to update its own
/// NodeInfo. Never exercised by this backend (no UpdateNodeInfo calls are
/// made), but `--node-controller-key` is required to be non-empty.
const HARNESS_CONTROLLER_KEY: &str =
    "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";
/// First gRPC port used by harness nodes. Chosen away from Docker's
/// published-port range (50051+) and orbis-node's own in-process test
/// harnesses (51051-51074) so nothing collides if run alongside them.
const HARNESS_BASE_PORT: u16 = 61_000;

/// A running in-process DKG network: `network_size` real orbis-node
/// instances sharing one [`DummyBulletin`] "chain". Dropping this tears down
/// every node (aborts its gRPC server task, removes its local storage file).
pub struct HarnessNetwork {
    pub endpoints: Vec<NodeEndpoint>,
    node_keys: Vec<String>,
    bulletin: Arc<DummyBulletin>,
    _nodes: Vec<HarnessNodeHandle>,
}

impl HarnessNetwork {
    /// Boot `network_size` in-process nodes on sequential loopback ports
    /// starting at [`HARNESS_BASE_PORT`], sharing one fresh `DummyBulletin`.
    /// `shaping` is applied to every node's own outbound traffic — pass
    /// `NetworkShapingProfile::NONE` (or any no-op profile) for an unshaped
    /// LAN-equivalent network. `pss_poll_interval_secs` sets every node's PSS
    /// scheduler wake-up interval (`0` disables PSS entirely for this
    /// network — cheaper when no case in this stack needs it).
    pub async fn spin_up(
        network_size: usize,
        stack_id: &str,
        shaping: NetworkShapingProfile,
        pss_poll_interval_secs: u64,
    ) -> Result<Self> {
        init_tracing_once();
        let bulletin = Arc::new(DummyBulletin::default());
        let runtime_base_path = std::env::temp_dir()
            .join("orbis-bench-harness")
            .join(stack_id);
        std::fs::create_dir_all(&runtime_base_path).with_context(|| {
            format!(
                "create harness runtime directory {}",
                runtime_base_path.display()
            )
        })?;

        let mut nodes = Vec::with_capacity(network_size);
        let mut endpoints = Vec::with_capacity(network_size);
        let mut node_keys = Vec::with_capacity(network_size);
        for index in 1..=network_size {
            let port = HARNESS_BASE_PORT
                .checked_add(u16::try_from(index - 1).context("network_size overflowed u16")?)
                .context("harness port range overflowed u16")?;
            let grpc_addr = format!("127.0.0.1:{port}");
            let db_path: PathBuf = runtime_base_path.join(format!("node-{index:03}.redb"));
            let params = HarnessNodeParams {
                grpc_addr: grpc_addr.clone(),
                db_path: db_path.to_string_lossy().into_owned(),
                password: format!("orbis-bench-harness-{stack_id}-{index}"),
                runtime_base_path: &runtime_base_path,
                policy_id: HARNESS_POLICY_ID.to_string(),
                node_controller_key: HARNESS_CONTROLLER_KEY.to_string(),
                network_shaping: (!shaping.is_noop()).then_some(shaping),
                pss_poll_interval_secs,
            };
            let handle = spawn_harness_node(params, bulletin.clone())
                .await
                .with_context(|| format!("spawn harness node {index}"))?;
            endpoints.push(NodeEndpoint {
                index,
                service: format!("harness-node-{index:03}"),
                grpc_url: handle.grpc_endpoint.clone(),
                // No Prometheus endpoint in this backend (see module docs on
                // `runner.rs::run_stack_in_process`) — resource/metric deltas
                // are simply omitted from harness trial records.
                metrics_url: String::new(),
            });
            node_keys.push(handle.node_key.clone());
            nodes.push(handle);
        }

        Ok(Self {
            endpoints,
            node_keys,
            bulletin,
            _nodes: nodes,
        })
    }

    /// Seed a pending (unfinalized) ring directly on the shared bulletin —
    /// the in-process equivalent of a live `MsgCreateRing`. `members` are
    /// 1-based indices into this network, matching `NodeEndpoint::index`.
    /// `pss_interval_secs` is the ring's own due-for-refresh interval
    /// (`RingPayload.pss_interval`) — unlike Docker's SourceHub-backed
    /// rings, `DummyBulletin` enforces no floor on this, so callers are free
    /// to use a short interval for PSS refresh trials.
    pub fn seed_pending_ring(
        &self,
        ring_id: &str,
        members: &[usize],
        threshold: usize,
        pss_interval_secs: u64,
    ) -> Result<()> {
        let peer_node_keys = members
            .iter()
            .map(|&index| {
                self.node_keys
                    .get(index - 1)
                    .cloned()
                    .with_context(|| format!("ring member {index} is outside the harness network"))
            })
            .collect::<Result<Vec<_>>>()?;
        let payload = RingPayload {
            ring_pk: String::new(),
            peer_node_keys,
            threshold: threshold as u32,
            pss_interval: pss_interval_secs,
            policy_id: Some(HARNESS_POLICY_ID.to_string()),
            ..Default::default()
        };
        self.bulletin
            .set_ring(ring_id.to_string(), payload)
            .map_err(|error| anyhow::anyhow!("seed pending ring {ring_id}: {error}"))
    }

    /// In-process equivalent of `cli_tool::post_key_derivation_with_config`:
    /// derives the SIGN public key locally and posts the `KeyDerivation`
    /// record directly to the shared bulletin via the same `Bulletin::post`
    /// path a real node's `StoreSecretService`/key-derivation handler uses —
    /// no chain client involved, unlike the Docker-only cli-tool function
    /// (which unconditionally builds a `SourceHubBulletin`). Returns
    /// `(derivation_id, derived_public_key_hex)`.
    pub async fn post_key_derivation(
        &self,
        ring_id: &str,
        ring_pk: &str,
        derivation: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
    ) -> Result<(String, String)> {
        let ring_pk_bytes = hex::decode(ring_pk).context("decode ring_pk hex")?;
        let ring_pk_point =
            GroupAffine::from_bytes(&ring_pk_bytes).context("parse ring_pk point")?;
        let metadata = SignImpl::encode_metadata(policy_id, resource, permission);
        let derived_pk =
            SignImpl::derive_public_key(&ring_pk_point, derivation.as_bytes(), Some(&metadata))
                .map_err(|error| anyhow::anyhow!("derive SIGN public key: {error}"))?;
        let derived_pk_hex = hex::encode(
            derived_pk
                .to_bytes()
                .context("serialize derived public key")?,
        );

        let key_derivation = KeyDerivation {
            ring_id: ring_id.to_string(),
            derivation: derivation.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
        };
        let payload = serde_json::to_vec(&key_derivation).context("serialize KeyDerivation")?;
        let derivation_id = self
            .bulletin
            .post(BulletinWriteKind::KeyDerivation, payload)
            .await
            .map_err(|error| anyhow::anyhow!("post KeyDerivation: {error}"))?;
        Ok((derivation_id, derived_pk_hex))
    }

    /// Node keys for every member of this network, 1-indexed the same way as
    /// [`HarnessNetwork::endpoints`] / `NodeEndpoint::index`.
    pub fn node_key(&self, index: usize) -> Result<&str> {
        self.node_keys
            .get(index - 1)
            .map(String::as_str)
            .with_context(|| format!("node {index} is outside the harness network"))
    }

    /// Poll the shared bulletin for `ring_id`'s finalization, then cross-check
    /// every committee member's local `GetRingState` (via `clients`, the same
    /// gRPC polling `protocol.rs`'s Docker-backed
    /// `wait_ring_finalized_everywhere` performs) so this only returns once
    /// the ring is finalized *and* converged everywhere, not just on-bulletin.
    pub async fn wait_ring_finalized_everywhere(
        &self,
        clients: &DirectClients,
        ring_id: &str,
        members: &[usize],
        deadline: Duration,
    ) -> Result<String> {
        tokio::time::timeout(deadline, async {
            let mut last_progress = tokio::time::Instant::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap_or_else(tokio::time::Instant::now);
            loop {
                if let Some(ring_pk) = self.ring_pk(ring_id).await? {
                    match clients.ring_states(members, &ring_pk).await {
                        Ok(states) => {
                            let expected_polynomial = states
                                .first()
                                .map(|state| state.public_polynomial.as_str())
                                .filter(|polynomial| !polynomial.is_empty());
                            if expected_polynomial.is_some()
                                && states.iter().all(|state| {
                                    Some(state.public_polynomial.as_str()) == expected_polynomial
                                })
                            {
                                return Ok::<_, anyhow::Error>(ring_pk);
                            }
                            if last_progress.elapsed() >= Duration::from_secs(10) {
                                eprintln!(
                                    "ring {ring_id}: finalized on bulletin; waiting for matching local state on {} committee nodes",
                                    members.len()
                                );
                                last_progress = tokio::time::Instant::now();
                            }
                        }
                        Err(error) => {
                            if last_progress.elapsed() >= Duration::from_secs(10) {
                                eprintln!(
                                    "ring {ring_id}: finalized on bulletin; local-state verification pending: {error:#}"
                                );
                                last_progress = tokio::time::Instant::now();
                            }
                        }
                    }
                } else if last_progress.elapsed() >= Duration::from_secs(10) {
                    eprintln!("ring {ring_id}: waiting for bulletin finalization");
                    last_progress = tokio::time::Instant::now();
                }
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .with_context(|| {
            format!("ring {ring_id} did not finalize on the bulletin and on every committee node")
        })?
    }

    /// Current ring public key on the shared bulletin, if the ring exists
    /// and has finalized (fresh DKG) or refreshed at least once. `None`
    /// while still pending, or if `ring_id` doesn't exist at all.
    pub async fn ring_pk(&self, ring_id: &str) -> Result<Option<String>> {
        match self
            .bulletin
            .read(ring_id.to_string(), BulletinKind::Ring)
            .await
        {
            Ok(post) => {
                let payload = RingPayload::try_from(post)
                    .map_err(|error| anyhow::anyhow!("parse ring {ring_id}: {error}"))?;
                Ok((!payload.ring_pk.is_empty()).then_some(payload.ring_pk))
            }
            Err(BulletinError::NotFound { .. }) => Ok(None),
            Err(error) => Err(anyhow::anyhow!("read ring {ring_id}: {error}")),
        }
    }
}
