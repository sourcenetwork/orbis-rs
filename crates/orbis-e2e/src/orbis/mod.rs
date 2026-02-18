mod health;
mod node;

pub use health::HealthCheckConfig;
pub use node::OrbisNode;

use crate::{allocate_ports, find_orbis_node_binary, ManagedProcess};
use crate::sourcehub::SourceHubNode;
use std::{
    fmt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// SourceHub URLs needed by orbis-node CLI args.
///
/// Data-only carrier — does not own or manage the SourceHub process.
#[derive(Clone, Debug)]
pub struct SourceHubUrls {
    pub grpc_url: String,
    pub comet_rpc_url: String,
    pub lcd_url: String,
}

impl From<&SourceHubNode> for SourceHubUrls {
    fn from(sh: &SourceHubNode) -> Self {
        Self {
            grpc_url: sh.grpc_url.clone(),
            comet_rpc_url: sh.comet_rpc_url.clone(),
            lcd_url: sh.lcd_url.clone(),
        }
    }
}

/// A running Orbis ring with managed node processes.
///
/// Does not own infrastructure (SourceHub, DefraDB, TestRunDir).
/// The caller is responsible for managing those lifetimes and ensuring
/// correct drop order (ring before infrastructure before run dir).
pub struct OrbisRing {
    nodes: Vec<OrbisNode>,
    threshold: u32,
}

impl fmt::Debug for OrbisRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrbisRing")
            .field("node_count", &self.nodes.len())
            .field("threshold", &self.threshold)
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
///
/// Requires `base_dir` and `identity_keys` to be set. Optionally accepts
/// `sourcehub_urls` to point orbis-node processes at a SourceHub instance.
pub struct OrbisRingBuilder {
    node_count: usize,
    threshold: u32,
    log_level: String,
    base_dir: Option<PathBuf>,
    identity_keys: Option<Vec<String>>,
    sourcehub_urls: Option<SourceHubUrls>,
}

impl fmt::Debug for OrbisRingBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrbisRingBuilder")
            .field("node_count", &self.node_count)
            .field("threshold", &self.threshold)
            .field("log_level", &self.log_level)
            .field("has_base_dir", &self.base_dir.is_some())
            .field("has_identity_keys", &self.identity_keys.is_some())
            .field("has_sourcehub_urls", &self.sourcehub_urls.is_some())
            .finish()
    }
}

impl Default for OrbisRingBuilder {
    fn default() -> Self {
        Self {
            node_count: 3,
            threshold: 2,
            log_level: "info".to_string(),
            base_dir: None,
            identity_keys: None,
            sourcehub_urls: None,
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

    /// Set the base directory for node subdirectories.
    ///
    /// Each node gets a `node{i}/` subdirectory under this path.
    #[must_use]
    pub fn base_dir(mut self, path: &Path) -> Self {
        self.base_dir = Some(path.to_path_buf());
        self
    }

    /// Set pre-generated identity keys (hex-encoded secp256k1 private keys).
    ///
    /// Must have exactly `node_count` keys. These are set as `ORBIS_SECRET_KEY`
    /// for each orbis-node process.
    #[must_use]
    pub fn identity_keys(mut self, keys: Vec<String>) -> Self {
        self.identity_keys = Some(keys);
        self
    }

    /// Set SourceHub URLs for orbis-node CLI args.
    ///
    /// If set, each orbis-node process gets `--authz-grpc`, `--bulletin-grpc`,
    /// `--chain-rpc`, and `--chain-rest` flags.
    #[must_use]
    pub fn sourcehub_urls(mut self, urls: SourceHubUrls) -> Self {
        self.sourcehub_urls = Some(urls);
        self
    }

    /// Build and start the ring.
    ///
    /// This will:
    /// 1. Find the orbis-node binary
    /// 2. Allocate gRPC ports
    /// 3. Create node subdirectories under `base_dir`
    /// 4. Spawn orbis-node processes with identity keys and optional SourceHub args
    /// 5. Return an OrbisRing handle (caller should call `wait_ready()`)
    pub async fn build(self) -> eyre::Result<OrbisRing> {
        let n = self.node_count;
        let binary = find_orbis_node_binary()?;

        let base_dir = self
            .base_dir
            .ok_or_else(|| eyre::eyre!("OrbisRingBuilder: base_dir is required"))?;

        let identity_keys = self
            .identity_keys
            .ok_or_else(|| eyre::eyre!("OrbisRingBuilder: identity_keys is required"))?;

        if identity_keys.len() != n {
            return Err(eyre::eyre!(
                "OrbisRingBuilder: expected {} identity keys, got {}",
                n,
                identity_keys.len()
            ));
        }

        let grpc_ports = allocate_ports(n)?;
        let mut nodes = Vec::with_capacity(n);

        for i in 0..n {
            let node_dir = base_dir.join(format!("node{}", i));
            std::fs::create_dir_all(&node_dir)?;
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

            if let Some(ref urls) = self.sourcehub_urls {
                cmd.args([
                    "--authz-grpc",
                    &urls.grpc_url,
                    "--bulletin-grpc",
                    &urls.grpc_url,
                    "--chain-rpc",
                    &urls.comet_rpc_url,
                    "--chain-rest",
                    &urls.lcd_url,
                ]);
            }

            cmd.env("ORBIS_PASSWORD", "e2e-test-password");
            cmd.env("ORBIS_SECRET_KEY", secret_hex);
            cmd.env("NO_COLOR", "1");
            cmd.env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| self.log_level.clone()),
            );

            let process = ManagedProcess::spawn(&format!("node{}", i), &mut cmd, &log_dir)?;

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
        })
    }
}
