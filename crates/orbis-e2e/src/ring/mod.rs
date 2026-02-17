mod health;
mod node;

pub use health::HealthCheckConfig;
pub use node::OrbisNode;

use crate::{
    allocate_ports, find_orbis_node_binary, generate_run_id, ManagedProcess, TestRunDir,
};
use crate::sourcehub::{self, SourceHubNode};
use std::{
    fmt,
    process::Command,
    time::Duration,
};

/// A running Orbis ring with managed node processes.
///
/// Field order matters: `nodes` must be dropped before `sourcehub` and `_run_dir`
/// so orbis processes are killed before SourceHub and the data directory.
pub struct OrbisRing {
    nodes: Vec<OrbisNode>,
    threshold: u32,
    sourcehub: Option<SourceHubNode>,
    _run_dir: TestRunDir,
}

impl fmt::Debug for OrbisRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrbisRing")
            .field("node_count", &self.nodes.len())
            .field("threshold", &self.threshold)
            .field("has_sourcehub", &self.sourcehub.is_some())
            .finish()
    }
}

impl OrbisRing {
    /// Create a new builder.
    pub fn builder() -> OrbisRingBuilder {
        OrbisRingBuilder::default()
    }

    /// Number of nodes in the ring.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Threshold for the ring.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Access a specific node.
    pub fn node(&self, index: usize) -> &OrbisNode {
        &self.nodes[index]
    }

    /// Access all nodes.
    pub fn nodes(&self) -> &[OrbisNode] {
        &self.nodes
    }

    /// Get all gRPC addresses.
    pub fn grpc_addrs(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.grpc_addr()).collect()
    }

    /// Access the SourceHub node (if started).
    pub fn sourcehub(&self) -> Option<&SourceHubNode> {
        self.sourcehub.as_ref()
    }

    /// Wait for all nodes' gRPC endpoints to become responsive.
    ///
    /// Polls each node's InfoService.GetNodeInfo in parallel.
    pub async fn wait_ready(&self, timeout: Duration) -> eyre::Result<()> {
        let config = HealthCheckConfig {
            poll_interval: Duration::from_millis(100),
            timeout,
        };
        health::wait_all_healthy(&self.grpc_addrs(), &config).await
    }
}

/// Builder for `OrbisRing`.
pub struct OrbisRingBuilder {
    node_count: usize,
    threshold: u32,
    log_level: String,
    with_sourcehub: bool,
    sourcehub_timeout: Duration,
}

impl fmt::Debug for OrbisRingBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrbisRingBuilder")
            .field("node_count", &self.node_count)
            .field("threshold", &self.threshold)
            .field("log_level", &self.log_level)
            .field("with_sourcehub", &self.with_sourcehub)
            .finish()
    }
}

impl Default for OrbisRingBuilder {
    fn default() -> Self {
        Self {
            node_count: 3,
            threshold: 2,
            log_level: "info".to_string(),
            with_sourcehub: false,
            sourcehub_timeout: Duration::from_secs(60),
        }
    }
}

impl OrbisRingBuilder {
    /// Set the number of nodes (default: 3).
    #[must_use]
    pub fn nodes(mut self, n: usize) -> Self {
        self.node_count = n;
        self
    }

    /// Set the DKG threshold (default: 2).
    #[must_use]
    pub fn threshold(mut self, t: u32) -> Self {
        self.threshold = t;
        self
    }

    /// Set the log level for orbis-node processes (default: "info").
    #[must_use]
    pub fn log_level(mut self, level: &str) -> Self {
        self.log_level = level.to_string();
        self
    }

    /// Enable SourceHub devnet. Provisions genesis, starts the chain, and
    /// points all orbis-node processes at it.
    #[must_use]
    pub fn with_sourcehub(mut self) -> Self {
        self.with_sourcehub = true;
        self
    }

    /// Set the SourceHub startup timeout (default: 60s).
    #[must_use]
    pub fn sourcehub_timeout(mut self, timeout: Duration) -> Self {
        self.sourcehub_timeout = timeout;
        self
    }

    /// Build and start the ring.
    ///
    /// This will:
    /// 1. Find the orbis-node binary
    /// 2. If `with_sourcehub`: start a SourceHub devnet (genesis, first block)
    /// 3. Allocate ports (gRPC per node)
    /// 4. Generate deterministic secrets per node
    /// 5. Spawn orbis-node processes pointed at SourceHub (if enabled)
    /// 6. Return an OrbisRing handle (caller should call `wait_ready()`)
    pub async fn build(self) -> eyre::Result<OrbisRing> {
        let n = self.node_count;
        let binary = find_orbis_node_binary()?;
        let run_id = generate_run_id();
        let run_dir = TestRunDir::new(&run_id)?;

        // Generate deterministic identity keys for each node
        // These are used both as ORBIS_SECRET_KEY and for SourceHub genesis funding
        let identity_keys: Vec<String> = (0..n)
            .map(|i| format!("{:0>64x}", u256_from_seed(&run_id, i)))
            .collect();

        // Optionally start SourceHub
        let sourcehub = if self.with_sourcehub {
            let sh_ports = sourcehub::allocate_source_hub_ports()?;
            let sh_home = run_dir.component_dir("sourcehub")?;
            let sh_log_dir = sh_home.join("logs");
            std::fs::create_dir_all(&sh_log_dir)?;

            let sh_node = SourceHubNode::start(
                sh_home,
                sh_log_dir,
                &sh_ports,
                &identity_keys,
                self.sourcehub_timeout,
            )
            .await?;

            Some(sh_node)
        } else {
            None
        };

        // Allocate one gRPC port per node
        let grpc_ports = allocate_ports(n)?;

        let mut nodes = Vec::with_capacity(n);

        for i in 0..n {
            let node_dir = run_dir.component_dir(&format!("node{}", i))?;
            let log_dir = node_dir.join("logs");
            let data_dir = node_dir.join("data");
            std::fs::create_dir_all(&data_dir)?;

            let secret_hex = &identity_keys[i];

            let mut cmd = Command::new(&binary);
            cmd.args([
                "--addr",
                &format!("127.0.0.1:{}", grpc_ports[i]),
                "--log-level",
                &self.log_level,
                "--data-dir",
                data_dir.to_str().unwrap_or("data"),
            ]);

            // Point at SourceHub if running
            if let Some(ref sh) = sourcehub {
                cmd.args([
                    "--authz-grpc",
                    &sh.grpc_url,
                    "--bulletin-grpc",
                    &sh.grpc_url,
                    "--chain-rpc",
                    &sh.comet_rpc_url,
                    "--chain-rest",
                    &sh.lcd_url,
                ]);
            }

            // Set env vars for password and secret key (avoid interactive prompt)
            cmd.env("ORBIS_PASSWORD", "e2e-test-password");
            cmd.env("ORBIS_SECRET_KEY", secret_hex);
            cmd.env("NO_COLOR", "1");
            cmd.env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| self.log_level.clone()),
            );

            let process =
                ManagedProcess::spawn(&format!("node{}", i), &mut cmd, &log_dir)?;

            nodes.push(OrbisNode {
                index: i,
                grpc_port: grpc_ports[i],
                data_dir: node_dir,
                log_dir,
                process,
            });
        }

        Ok(OrbisRing {
            nodes,
            threshold: self.threshold,
            sourcehub,
            _run_dir: run_dir,
        })
    }
}

/// Generate a deterministic 256-bit value from run_id and node index.
/// Used for reproducible secret keys in tests.
fn u256_from_seed(run_id: &str, node_index: usize) -> u128 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    run_id.hash(&mut hasher);
    node_index.hash(&mut hasher);
    let h1 = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    node_index.hash(&mut hasher2);
    let h2 = hasher2.finish();

    ((h1 as u128) << 64) | (h2 as u128)
}
