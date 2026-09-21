//! Benchmark orchestration: resolves an `Experiment` into stacks/cases, runs each
//! stack against whichever execution backend it's configured for, and manages
//! shared run-level bookkeeping (the manifest, resume, interruption, host
//! metadata). The two backends' own logic lives in `docker` (Docker Compose +
//! a real chain) and `in_process` (real orbis-node instances as tokio tasks,
//! no Docker, no chain); what's shared between them lives in `trial`.

mod docker;
mod in_process;
mod trial;

use trial::*;

/// Re-exported so `protocol.rs` can keep calling `crate::runner::read_ring_with_retry`
/// without needing to know it now lives in the Docker backend module.
pub(crate) use docker::read_ring_with_retry;

use crate::compose::{
    node_service, write_stack_files, ComposeInput, RingDefinition, CONTROLLER_PUBLIC_KEY,
    RING_GOVERNANCE_POLICY_ID,
};
#[cfg(test)]
use crate::config::NetworkProfile;
use crate::config::{
    ExecutionBackend, Experiment, Operation, RingCase, StackPlan, PSS_GRACE_PERIOD_SECS,
};
use crate::docker::{image_digest, DockerCompose};
use crate::harness::{HarnessNetwork, HARNESS_POLICY_ID};
use crate::metrics::{aggregate, delta, retain_benchmark_metrics, scrape, MetricSnapshot};
use crate::protocol::{
    discover_node_identity, sign_call, wait_nodes_ready, DirectClients, NodeEndpoint, NodeIdentity,
    PreFixture, PssRefreshTimeout, SignFixture,
};
use crate::report::generate_report;
use crate::results::{
    read_trials, HostMetadata, ResultStore, RunManifest, RunStatus, SetupFailureRecord, TrialRecord,
};
use crate::setup::{
    create_ring_governance_policy, create_rings_on_chain, fund_nodes, register_ring_governance,
    update_peer_addresses,
};
use anyhow::{bail, Context, Result};
use common::blockchain::{orbis::Ring, ChainConfig, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY};
use crypto::helpers::generate_keypair;
use crypto::r#trait::{Dkg, ThresholdDealer, ThresholdSigner};
use crypto::{CryptoSerialize, DkgImpl, PreImpl, SignImpl};
use futures::future::join_all;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

/// Protocol version stamped on rings created for this benchmark. Matches
/// `network::V0.version` without pulling in the network crate just for one
/// constant.
const RING_PROTOCOL_VERSION: u64 = 0;

#[derive(Clone, Debug, Default)]
pub struct RunOptions {
    pub resume: Option<PathBuf>,
    pub keep_network: bool,
    pub stop_after_two_non_viable_sizes: bool,
}

pub struct BenchmarkRunner {
    experiment: Experiment,
    options: RunOptions,
    repository_root: PathBuf,
}

#[derive(Debug)]
pub struct BenchmarkInterrupted {
    run_dir: PathBuf,
}

impl BenchmarkInterrupted {
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }
}

impl fmt::Display for BenchmarkInterrupted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "benchmark interrupted; partial evidence: {}",
            self.run_dir.display()
        )
    }
}

impl std::error::Error for BenchmarkInterrupted {}

enum StackRunOutcome {
    Completed(bool),
    Interrupted,
}

impl BenchmarkRunner {
    pub fn new(experiment: Experiment, options: RunOptions) -> Result<Self> {
        experiment.validate()?;
        Ok(Self {
            experiment,
            options,
            repository_root: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
        })
    }

    pub async fn run(self) -> Result<PathBuf> {
        let (interrupt_tx, interrupt_rx) = watch::channel(false);
        let signal_task = tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    interrupt_tx.send(true).ok();
                }
                Err(error) => {
                    eprintln!("failed to install Ctrl-C handler: {error}");
                }
            }
        });
        let result = self.run_with_interrupt(interrupt_rx).await;
        signal_task.abort();
        result
    }

    async fn run_with_interrupt(
        mut self,
        mut interrupt_rx: watch::Receiver<bool>,
    ) -> Result<PathBuf> {
        let (mut store, mut manifest) = if let Some(run_dir) = &self.options.resume {
            let (store, mut manifest) = ResultStore::resume(run_dir.clone())?;
            self.experiment = manifest.experiment.clone();
            manifest.status = RunStatus::Running;
            manifest.completed_at_unix_ms = None;
            store.update_manifest(&manifest)?;
            (store, manifest)
        } else {
            let run_id = new_run_id(&self.experiment.name);
            let run_dir = self.experiment.output_dir.join(&run_id);
            let manifest = RunManifest {
                schema_version: self.experiment.schema_version,
                run_id,
                created_at_unix_ms: unix_ms(),
                completed_at_unix_ms: None,
                status: RunStatus::Running,
                experiment: self.experiment.clone(),
                host: host_metadata(),
                vera_ref: self.experiment.vera_ref.clone(),
                node_image: None,
                vera_image: None,
                crypto_implementation: format!(
                    "dkg={}; pre={}; sign={}",
                    <DkgImpl as Dkg>::name(),
                    <PreImpl as ThresholdDealer>::name(),
                    <SignImpl as ThresholdSigner>::name()
                ),
                stack_projects: Vec::new(),
                profile_calibration: BTreeMap::new(),
                setup_batch_evidence: BTreeMap::new(),
                warnings: vec![match self.experiment.backend {
                    ExecutionBackend::Docker => "Single-host Docker measurements include host scheduling and resource contention; they are not a universal protocol maximum.".into(),
                    ExecutionBackend::InProcess => "In-process measurements run every node as a task in one process on one host, sharing its scheduler and CPU cores; they are not a universal protocol maximum and do not include container or chain overhead.".into(),
                }],
            };
            (ResultStore::create(run_dir, &manifest)?, manifest)
        };

        let completed = completed_trial_keys(store.root())?;
        let mut plan = if self.options.stop_after_two_non_viable_sizes {
            self.experiment.resolve_capacity_sweep()?
        } else {
            self.experiment.resolve()?
        };
        plan.assign_indices();
        eprintln!(
            "benchmark run {}: {} stack(s); evidence will be written to {}",
            manifest.run_id,
            plan.stacks.len(),
            store.root().display()
        );
        let mut consecutive_non_viable = 0usize;
        let mut current_ring_size = None;
        let mut current_size_viable = true;
        let mut interrupted = false;

        for (stack_position, stack) in plan.stacks.iter().enumerate() {
            if *interrupt_rx.borrow() {
                interrupted = true;
                break;
            }
            let stack_ring_size = stack.cases.iter().map(|case| case.ring_size).max();
            if self.options.stop_after_two_non_viable_sizes
                && current_ring_size.is_some()
                && stack_ring_size != current_ring_size
            {
                consecutive_non_viable = if current_size_viable {
                    0
                } else {
                    consecutive_non_viable + 1
                };
                if consecutive_non_viable >= 2 {
                    manifest.warnings.push(
                        "Capacity sweep stopped after two consecutive non-viable sizes".into(),
                    );
                    break;
                }
                current_size_viable = true;
            }
            current_ring_size = stack_ring_size;
            let stack_id = format!(
                "orbis-bench-{}-s{:03}",
                short_id(&manifest.run_id),
                stack.stack_index
            );
            if !manifest.stack_projects.contains(&stack_id) {
                manifest.stack_projects.push(stack_id.clone());
                store.update_manifest(&manifest)?;
            }
            eprintln!(
                "[{}/{}] stack {}: profile={}, nodes={}, cases={}",
                stack_position + 1,
                plan.stacks.len(),
                stack_id,
                stack.profile.name,
                stack.network_size,
                stack.cases.len()
            );
            let result = self
                .run_stack(
                    &mut store,
                    &mut manifest,
                    stack,
                    &stack_id,
                    &completed,
                    &mut interrupt_rx,
                )
                .await;
            let case_viability = match result {
                Ok(StackRunOutcome::Completed(viability)) => viability,
                Ok(StackRunOutcome::Interrupted) => {
                    interrupted = true;
                    break;
                }
                Err(error) => {
                    eprintln!("[{stack_id}] setup failed: {error:#}");
                    store.append_setup_failure(&SetupFailureRecord {
                        run_id: manifest.run_id.clone(),
                        stack_id: stack_id.clone(),
                        profile: stack.profile.name.clone(),
                        network_size: stack.network_size,
                        recorded_at_unix_ms: unix_ms(),
                        error_class: "setup_failure".into(),
                        error: format!("{error:#}"),
                    })?;
                    manifest
                        .warnings
                        .push(format!("stack {stack_id} setup failed: {error:#}"));
                    store.update_manifest(&manifest)?;
                    false
                }
            };

            if self.options.stop_after_two_non_viable_sizes {
                current_size_viable &= case_viability;
            }
        }

        manifest.completed_at_unix_ms = Some(unix_ms());
        if interrupted {
            manifest.status = RunStatus::Interrupted;
            manifest
                .warnings
                .push("Benchmark interrupted by Ctrl-C; partial evidence was preserved.".into());
            store.update_manifest(&manifest)?;
            store.write_summary()?;
            if let Err(error) = generate_report(store.root()) {
                manifest.warnings.push(format!(
                    "interrupted-run report generation failed: {error:#}"
                ));
                store.update_manifest(&manifest)?;
            }
            eprintln!(
                "benchmark run {} interrupted; partial evidence: {}",
                manifest.run_id,
                store.root().display()
            );
            return Err(BenchmarkInterrupted {
                run_dir: store.root().to_path_buf(),
            }
            .into());
        }

        manifest.status = RunStatus::Completed;
        store.update_manifest(&manifest)?;
        store.write_summary()?;
        if let Err(error) = generate_report(store.root()) {
            manifest.status = RunStatus::Failed;
            store.update_manifest(&manifest)?;
            return Err(error);
        }
        eprintln!(
            "benchmark run {} complete; report: {}",
            manifest.run_id,
            store.root().join("report.html").display()
        );
        Ok(store.root().to_path_buf())
    }

    async fn run_stack(
        &self,
        store: &mut ResultStore,
        manifest: &mut RunManifest,
        stack: &StackPlan,
        stack_id: &str,
        completed: &HashSet<TrialKey>,
        interrupt_rx: &mut watch::Receiver<bool>,
    ) -> Result<StackRunOutcome> {
        if self.experiment.backend == ExecutionBackend::InProcess {
            return self
                .run_stack_in_process(store, manifest, stack, stack_id, completed, interrupt_rx)
                .await;
        }
        self.run_stack_docker(store, manifest, stack, stack_id, completed, interrupt_rx)
            .await
    }
}

async fn wait_for_interrupt(interrupt_rx: &mut watch::Receiver<bool>) {
    if *interrupt_rx.borrow() {
        return;
    }
    loop {
        if interrupt_rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
        if *interrupt_rx.borrow() {
            return;
        }
    }
}

fn new_run_id(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!(
        "{}-{}-{}",
        unix_secs(),
        safe.trim_matches('-'),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )
}

fn short_id(run_id: &str) -> String {
    let digest = Sha256::digest(run_id.as_bytes());
    hex::encode(&digest[..4])
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn host_metadata() -> HostMetadata {
    let git_commit = command_output("git", &["rev-parse", "HEAD"]);
    let git_dirty =
        command_output("git", &["status", "--porcelain"]).map(|output| !output.is_empty());
    HostMetadata {
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        cpu_count: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1),
        cpu_model: command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(linux_cpu_model),
        host_memory_bytes: command_output("sysctl", &["-n", "hw.memsize"])
            .and_then(|value| value.parse().ok())
            .or_else(linux_memory_bytes),
        disk_available_bytes: command_output("df", &["-Pk", "."])
            .and_then(|output| output.lines().last().map(str::to_string))
            .and_then(|line| line.split_ascii_whitespace().nth(3)?.parse::<u64>().ok())
            .map(|kib| kib.saturating_mul(1_024)),
        git_commit,
        git_dirty,
        docker_version: command_output("docker", &["version", "--format", "{{.Server.Version}}"]),
        docker_info: command_output("docker", &["info", "--format", "{{json .}}"])
            .and_then(|text| serde_json::from_str(&text).ok()),
    }
}

fn linux_cpu_model() -> Option<String> {
    fs::read_to_string("/proc/cpuinfo")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("model name\t:").map(str::trim))
        .map(str::to_string)
}

fn linux_memory_bytes() -> Option<u64> {
    let kib = fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .split_ascii_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    Some(kib.saturating_mul(1_024))
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interrupt_waiter_observes_an_existing_signal() {
        let (interrupt_tx, mut interrupt_rx) = watch::channel(false);
        interrupt_tx.send(true).unwrap();

        timeout(
            Duration::from_millis(100),
            wait_for_interrupt(&mut interrupt_rx),
        )
        .await
        .expect("interrupt waiter should complete");
    }

    #[tokio::test]
    async fn interrupt_waiter_observes_a_later_signal() {
        let (interrupt_tx, mut interrupt_rx) = watch::channel(false);
        tokio::spawn(async move {
            interrupt_tx.send(true).unwrap();
        });

        timeout(
            Duration::from_millis(100),
            wait_for_interrupt(&mut interrupt_rx),
        )
        .await
        .expect("interrupt waiter should complete");
    }

    #[tokio::test]
    async fn interruption_preserves_evidence_and_marks_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let mut experiment = Experiment::single(3, 3, 2);
        experiment.output_dir = temp.path().join("results");
        let runner = BenchmarkRunner::new(experiment, RunOptions::default()).unwrap();
        let (interrupt_tx, interrupt_rx) = watch::channel(false);
        interrupt_tx.send(true).unwrap();

        let error = runner.run_with_interrupt(interrupt_rx).await.unwrap_err();
        let interrupted = error
            .downcast_ref::<BenchmarkInterrupted>()
            .expect("interruption should use the typed error");
        let manifest: RunManifest =
            serde_json::from_slice(&fs::read(interrupted.run_dir().join("manifest.json")).unwrap())
                .unwrap();

        assert_eq!(manifest.status, RunStatus::Interrupted);
        assert!(manifest.completed_at_unix_ms.is_some());
        assert!(interrupted.run_dir().join("summary.csv").is_file());
        assert!(interrupted.run_dir().join("report.html").is_file());
    }
}
