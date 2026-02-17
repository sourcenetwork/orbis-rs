use std::path::Path;
use std::process::Command;

use super::SourceHubPorts;

const VALIDATOR_STAKE: &str = "100000000000uopen";
const VALIDATOR_BALANCE: &str = "1000000000000uopen";
const IDENTITY_BALANCE: &str = "100000000uopen";
/// Large balance for the faucet account so it can fund all orbis-node signing addresses.
const FAUCET_BALANCE: &str = "100000000000uopen";

/// Provision a single-node SourceHub devnet genesis.
///
/// Follows the standard Cosmos SDK pattern:
///   init -> keys add -> add-genesis-account (validator + funded addrs + faucet) ->
///   gentx -> collect-gentxs -> patch configs
///
/// `faucet_address` is the well-known test account that orbis-node's
/// `integration-test` feature uses to fund each node's chain signing address.
pub fn provision_genesis(
    home_dir: &Path,
    chain_id: &str,
    funded_addresses: &[String],
    faucet_address: Option<&str>,
    ports: &SourceHubPorts,
) -> eyre::Result<()> {
    run_cmd(
        "sourcehubd",
        &[
            "init",
            "test-node",
            "--chain-id",
            chain_id,
            "--home",
            &home_dir.display().to_string(),
        ],
    )?;

    let validator_output = run_cmd(
        "sourcehubd",
        &[
            "keys",
            "add",
            "validator",
            "--keyring-backend",
            "test",
            "--home",
            &home_dir.display().to_string(),
            "--output",
            "json",
        ],
    )?;

    let addr_json: serde_json::Value = serde_json::from_str(&validator_output)
        .map_err(|e| eyre::eyre!("failed to parse validator key output: {}", e))?;
    let validator_address = addr_json["address"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing address in validator key output"))?
        .to_string();

    run_cmd(
        "sourcehubd",
        &[
            "genesis",
            "add-genesis-account",
            &validator_address,
            VALIDATOR_BALANCE,
            "--home",
            &home_dir.display().to_string(),
        ],
    )?;

    for addr in funded_addresses {
        run_cmd(
            "sourcehubd",
            &[
                "genesis",
                "add-genesis-account",
                addr,
                IDENTITY_BALANCE,
                "--home",
                &home_dir.display().to_string(),
            ],
        )
        .map_err(|e| eyre::eyre!("add genesis account {} failed: {}", addr, e))?;
    }

    // Fund the faucet account (used by orbis-node's integration-test feature to
    // transfer funds to each node's dynamically-generated chain signing address).
    if let Some(faucet_addr) = faucet_address {
        run_cmd(
            "sourcehubd",
            &[
                "genesis",
                "add-genesis-account",
                faucet_addr,
                FAUCET_BALANCE,
                "--home",
                &home_dir.display().to_string(),
            ],
        )
        .map_err(|e| eyre::eyre!("add faucet genesis account failed: {}", e))?;
    }

    run_cmd(
        "sourcehubd",
        &[
            "genesis",
            "gentx",
            "validator",
            VALIDATOR_STAKE,
            "--chain-id",
            chain_id,
            "--keyring-backend",
            "test",
            "--home",
            &home_dir.display().to_string(),
        ],
    )?;

    run_cmd(
        "sourcehubd",
        &[
            "genesis",
            "collect-gentxs",
            "--home",
            &home_dir.display().to_string(),
        ],
    )?;

    patch_config_toml(home_dir, ports)?;
    patch_app_toml(home_dir, ports)?;

    Ok(())
}

/// Patch config.toml to bind CometBFT RPC and P2P to allocated ports.
fn patch_config_toml(home_dir: &Path, ports: &SourceHubPorts) -> eyre::Result<()> {
    let config_path = home_dir.join("config/config.toml");
    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| eyre::eyre!("read config.toml: {}", e))?;

    let content = content.replace(
        "laddr = \"tcp://127.0.0.1:26657\"",
        &format!("laddr = \"tcp://0.0.0.0:{}\"", ports.comet_rpc),
    );
    let content = content.replace(
        "laddr = \"tcp://0.0.0.0:26656\"",
        &format!("laddr = \"tcp://0.0.0.0:{}\"", ports.p2p),
    );

    std::fs::write(&config_path, content)
        .map_err(|e| eyre::eyre!("write config.toml: {}", e))?;
    Ok(())
}

/// Patch app.toml to bind gRPC and LCD/API to allocated ports.
fn patch_app_toml(home_dir: &Path, ports: &SourceHubPorts) -> eyre::Result<()> {
    let app_path = home_dir.join("config/app.toml");
    let content = std::fs::read_to_string(&app_path)
        .map_err(|e| eyre::eyre!("read app.toml: {}", e))?;

    let content = content.replace(
        "address = \"0.0.0.0:9090\"",
        &format!("address = \"0.0.0.0:{}\"", ports.grpc),
    );
    let content = content.replace(
        "address = \"tcp://0.0.0.0:1317\"",
        &format!("address = \"tcp://0.0.0.0:{}\"", ports.lcd),
    );
    // Ensure API is enabled
    let content = content.replacen("enable = false", "enable = true", 1);

    std::fs::write(&app_path, content)
        .map_err(|e| eyre::eyre!("write app.toml: {}", e))?;
    Ok(())
}

fn run_cmd(program: &str, args: &[&str]) -> eyre::Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| eyre::eyre!("failed to run {} {}: {}", program, args.join(" "), e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(eyre::eyre!(
            "{} {} failed (exit {}): stderr={}, stdout={}",
            program,
            args.join(" "),
            output.status,
            stderr.trim(),
            stdout.trim()
        ))
    }
}
