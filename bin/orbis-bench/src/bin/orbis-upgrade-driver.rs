use anyhow::Result;
use clap::{Parser, Subcommand};
use orbis_bench::upgrade::{prepare_upgrade_fixture, run_upgrade_node, verify_upgrade_fixture};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "orbis-upgrade-driver",
    version,
    about = "Revision-local worker for the Orbis cross-commit upgrade harness"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one production-feature node behind the stable upgrade-test contract.
    Node {
        #[arg(long)]
        index: usize,
    },
    /// Build and verify the baseline fixture, then write manifest v1.
    Prepare {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        baseline_sha: String,
        #[arg(long)]
        crypto: String,
        #[arg(long)]
        sourcehub_ref: String,
    },
    /// Reopen the baseline fixture using the target revision and complete reshare checks.
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        result: PathBuf,
        #[arg(long)]
        target_sha: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Node { index } => run_upgrade_node(index).await,
        Command::Prepare {
            manifest,
            baseline_sha,
            crypto,
            sourcehub_ref,
        } => {
            let fixture =
                prepare_upgrade_fixture(&manifest, baseline_sha, crypto, sourcehub_ref).await?;
            println!(
                "baseline fixture ready: ring_id={} ring_pk={}",
                fixture.ring.ring_id, fixture.ring.ring_pk
            );
            Ok(())
        }
        Command::Verify {
            manifest,
            result,
            target_sha,
        } => {
            let evidence = verify_upgrade_fixture(&manifest, &result, target_sha).await?;
            println!(
                "upgrade verified: crypto={} final_committee=1,2,4",
                evidence.crypto
            );
            Ok(())
        }
    }
}
