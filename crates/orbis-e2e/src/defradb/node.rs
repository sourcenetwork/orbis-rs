use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::ManagedProcess;

use super::DefraDbPorts;

/// A running DefraDB node (v0.5.0).
///
/// Spawns `defra start` with in-memory storage and minimal overhead
/// for fast test cycles. Killed on drop via ManagedProcess.
pub struct DefraDbNode {
    #[allow(dead_code)]
    process: ManagedProcess,
    /// HTTP API URL (e.g. "http://127.0.0.1:9181").
    pub http_url: String,
    /// P2P multiaddr (e.g. "/ip4/127.0.0.1/tcp/9171").
    pub p2p_addr: String,
    /// Root directory for this node's data.
    #[allow(dead_code)]
    pub root_dir: PathBuf,
}

impl DefraDbNode {
    /// Start a DefraDB node.
    ///
    /// Uses in-memory store, disables encryption/signing/telemetry for speed.
    /// Optionally connects to a SourceHub instance for ACP and accepts an
    /// identity key for authenticated operations.
    ///
    /// When `identity_key` is provided:
    /// - Uses `--keyring-backend file` with password from `DEFRA_KEYRING_SECRET`
    /// - Passes `-i <hex_key>` to set the node's identity
    ///
    /// When `identity_key` is None:
    /// - Uses `--no-keyring` (ephemeral identity, no ACP signing)
    pub async fn start(
        root_dir: PathBuf,
        log_dir: PathBuf,
        ports: &DefraDbPorts,
        binary: &std::path::Path,
        sourcehub: Option<&SourceHubConfig>,
        identity_key: Option<&str>,
        orbis_signer: Option<&OrbisSignerConfig>,
        ready_timeout: Duration,
    ) -> eyre::Result<Self> {
        let http_addr = format!("127.0.0.1:{}", ports.http);
        let p2p_addr = format!("/ip4/127.0.0.1/tcp/{}", ports.p2p);

        let mut cmd = Command::new(binary);
        cmd.arg("--rootdir").arg(&root_dir);
        cmd.arg("--url").arg(&http_addr);
        cmd.arg("--no-log-color");

        // Keyring: file-based if identity provided, disabled otherwise
        if let Some(key_hex) = identity_key {
            let keyring_path = root_dir.join("keys");
            std::fs::create_dir_all(&keyring_path)?;
            cmd.arg("--keyring-backend").arg("file");
            cmd.arg("--keyring-path")
                .arg(keyring_path.to_str().unwrap_or("keys"));
            cmd.env("DEFRA_KEYRING_SECRET", "e2e-test-password");
            cmd.arg("start");
            cmd.arg("-i").arg(key_hex);
        } else {
            cmd.arg("start");
            cmd.arg("--no-keyring");
        }

        cmd.arg("--store").arg("memory");
        cmd.arg("--no-telemetry");
        cmd.arg("--no-encryption");

        // Signing: either delegate to Orbis ring or disable entirely
        if let Some(signer) = orbis_signer {
            cmd.arg("--signer-type").arg("orbis");
            cmd.arg("--signer-orbis-endpoint").arg(&signer.endpoint);
            cmd.arg("--signer-orbis-ring-id").arg(&signer.ring_id);
            cmd.arg("--signer-orbis-derivation").arg(&signer.derivation);
        } else {
            cmd.arg("--no-signing");
        }

        cmd.arg("--p2paddr").arg(&p2p_addr);

        if let Some(sh) = sourcehub {
            cmd.arg("--source-hub-address").arg(&sh.lcd_url);
            cmd.arg("--source-hub-comet-address").arg(&sh.comet_rpc_url);
            cmd.arg("--source-hub-chain-id").arg(&sh.chain_id);
            cmd.arg("--acp-document-type").arg("source-hub");
        }

        let process = ManagedProcess::spawn("defra", &mut cmd, &log_dir)?;

        let http_url = format!("http://{}", http_addr);

        // Poll health check endpoint until ready
        let client = reqwest::Client::new();
        let health_url = format!("{}/health-check", http_url);
        let deadline = tokio::time::Instant::now() + ready_timeout;
        loop {
            match client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => break,
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "defra health check timed out at {}",
                    health_url
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tracing::info!(
            http = %http_url,
            p2p = %p2p_addr,
            identity = identity_key.is_some(),
            "DefraDB node ready"
        );

        Ok(Self {
            process,
            http_url,
            p2p_addr,
            root_dir,
        })
    }

    /// HTTP API URL (e.g. "http://127.0.0.1:9181").
    pub fn http_url(&self) -> &str {
        &self.http_url
    }

    /// P2P multiaddr (e.g. "/ip4/127.0.0.1/tcp/9171").
    pub fn p2p_addr(&self) -> &str {
        &self.p2p_addr
    }
}

/// Minimal SourceHub connection info for DefraDB's ACP integration.
pub struct SourceHubConfig {
    pub lcd_url: String,
    pub comet_rpc_url: String,
    pub chain_id: String,
}

/// Configuration for DefraDB's Orbis signer integration.
///
/// When provided, DefraDB delegates document signing to an Orbis ring
/// via gRPC threshold signing instead of using a local key.
pub struct OrbisSignerConfig {
    /// gRPC endpoint of an Orbis node (e.g. "http://127.0.0.1:8081").
    pub endpoint: String,
    /// Ring ID to sign with (from DKG bulletin post).
    pub ring_id: String,
    /// Derivation label (e.g. "x-archive") for derived key signing.
    pub derivation: String,
}
