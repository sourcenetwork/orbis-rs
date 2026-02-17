use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::ManagedProcess;

use super::genesis;
use super::identity::source_hub_address;
use super::SourceHubPorts;

const DEFAULT_CHAIN_ID: &str = "sourcehub-localnet";

/// Well-known test account private key (the "abandon" mnemonic, Cosmos HD path m/44'/118'/0'/0/0).
/// Used as the faucet for orbis-node's `integration-test` feature to fund node signing addresses.
const TEST_ACCOUNT_HEX_KEY: &str =
    "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";

/// A running SourceHub single-node devnet.
///
/// Provisions genesis, starts the chain, and waits for the first block.
/// Killed on drop via ManagedProcess.
pub struct SourceHubNode {
    #[allow(dead_code)]
    process: ManagedProcess,
    /// Cosmos LCD/REST API URL (e.g. "http://127.0.0.1:1317").
    pub lcd_url: String,
    /// CometBFT RPC URL (e.g. "http://127.0.0.1:26657").
    pub comet_rpc_url: String,
    /// gRPC URL (e.g. "http://127.0.0.1:9090").
    pub grpc_url: String,
    /// Chain ID.
    pub chain_id: String,
    /// SourceHub home directory.
    #[allow(dead_code)]
    pub home_dir: PathBuf,
}

impl SourceHubNode {
    /// Provision and start a SourceHub devnet node.
    ///
    /// `identity_keys` are hex-encoded secp256k1 private keys whose derived
    /// `source1...` addresses will be funded in genesis.
    pub async fn start(
        home_dir: PathBuf,
        log_dir: PathBuf,
        ports: &SourceHubPorts,
        identity_keys: &[String],
        ready_timeout: Duration,
    ) -> eyre::Result<Self> {
        let chain_id = DEFAULT_CHAIN_ID.to_string();

        // Derive source1... addresses from private keys for genesis funding
        let funded_addresses: Vec<String> = identity_keys
            .iter()
            .map(|key| source_hub_address(key))
            .collect::<eyre::Result<_>>()?;

        // Derive the faucet address from the well-known test account key
        let faucet_address = source_hub_address(TEST_ACCOUNT_HEX_KEY)?;

        genesis::provision_genesis(
            &home_dir,
            &chain_id,
            &funded_addresses,
            Some(&faucet_address),
            ports,
        )?;

        let mut cmd = Command::new("sourcehubd");
        cmd.arg("start");
        cmd.arg("--home").arg(&home_dir);
        cmd.arg("--rpc.laddr")
            .arg(format!("tcp://0.0.0.0:{}", ports.comet_rpc));
        cmd.arg("--grpc.address")
            .arg(format!("0.0.0.0:{}", ports.grpc));
        cmd.arg("--api.address")
            .arg(format!("tcp://0.0.0.0:{}", ports.lcd));
        cmd.arg("--p2p.laddr")
            .arg(format!("tcp://0.0.0.0:{}", ports.p2p));
        cmd.arg("--minimum-gas-prices").arg("0uopen");
        cmd.arg("--log_no_color");

        let process = ManagedProcess::spawn("sourcehub", &mut cmd, &log_dir)?;

        let lcd_url = format!("http://127.0.0.1:{}", ports.lcd);

        // Wait for chain to produce its first block by polling the LCD endpoint
        let client = reqwest::Client::new();
        let health_url = format!(
            "{}/cosmos/base/tendermint/v1beta1/blocks/latest",
            lcd_url
        );
        let deadline = tokio::time::Instant::now() + ready_timeout;
        loop {
            match client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => break,
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "sourcehubd LCD health check timed out at {}",
                    health_url
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        tracing::info!(
            lcd = %lcd_url,
            comet_rpc = %format!("http://127.0.0.1:{}", ports.comet_rpc),
            grpc = %format!("http://127.0.0.1:{}", ports.grpc),
            "SourceHub devnet ready"
        );

        Ok(Self {
            process,
            lcd_url,
            comet_rpc_url: format!("http://127.0.0.1:{}", ports.comet_rpc),
            grpc_url: format!("http://127.0.0.1:{}", ports.grpc),
            chain_id,
            home_dir,
        })
    }
}
