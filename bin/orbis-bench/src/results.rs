use crate::config::{CryptoFeature, Experiment, Operation, RingCase};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostMetadata {
    pub os: String,
    pub architecture: String,
    pub cpu_count: usize,
    #[serde(default)]
    pub cpu_model: Option<String>,
    #[serde(default)]
    pub host_memory_bytes: Option<u64>,
    #[serde(default)]
    pub disk_available_bytes: Option<u64>,
    pub git_commit: Option<String>,
    pub git_dirty: Option<bool>,
    pub docker_version: Option<String>,
    pub docker_info: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub created_at_unix_ms: u128,
    pub completed_at_unix_ms: Option<u128>,
    pub status: RunStatus,
    pub experiment: Experiment,
    pub host: HostMetadata,
    pub vera_ref: String,
    pub node_image: Option<String>,
    pub vera_image: Option<String>,
    #[serde(default)]
    pub crypto_implementation: String,
    #[serde(default)]
    pub stack_projects: Vec<String>,
    #[serde(default)]
    pub profile_calibration: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub setup_batch_evidence: BTreeMap<String, serde_json::Value>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
    Interrupted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrialRecord {
    pub run_id: String,
    pub stack_id: String,
    pub profile: String,
    pub network_size: usize,
    pub case: RingCase,
    pub operation: Operation,
    pub trial_index: usize,
    pub warmup: bool,
    pub concurrency: Option<usize>,
    pub started_at_unix_ms: u128,
    pub duration_ms: f64,
    pub client_total_ms: Option<f64>,
    pub acknowledgement_ms: Option<f64>,
    pub verification_ms: Option<f64>,
    pub scheduler_delay_ms: Option<f64>,
    pub throughput_per_sec: Option<f64>,
    pub successful_requests: Option<u64>,
    pub failed_requests: Option<u64>,
    pub latency_p50_ms: Option<f64>,
    pub latency_p95_ms: Option<f64>,
    pub latency_p99_ms: Option<f64>,
    pub success: bool,
    pub error_class: Option<String>,
    pub error: Option<String>,
    pub ring_id: Option<String>,
    pub ring_pk: Option<String>,
    #[serde(default)]
    pub metric_deltas: BTreeMap<String, f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceSample {
    pub run_id: String,
    pub stack_id: String,
    pub sampled_at_unix_ms: u128,
    pub service: String,
    pub container_id: String,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub block_read_bytes: Option<u64>,
    pub block_write_bytes: Option<u64>,
    pub pids: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetupFailureRecord {
    pub run_id: String,
    pub stack_id: String,
    pub profile: String,
    pub network_size: usize,
    pub recorded_at_unix_ms: u128,
    pub error_class: String,
    pub error: String,
}

pub struct ResultStore {
    root: PathBuf,
    trials: File,
    setup_failures: File,
    resources: File,
}

impl ResultStore {
    pub fn create(root: PathBuf, manifest: &RunManifest) -> Result<Self> {
        fs::create_dir_all(root.join("logs"))
            .with_context(|| format!("create run directory {}", root.display()))?;
        write_json_atomic(&root.join("manifest.json"), manifest)?;
        let trials = append_file(&root.join("trials.jsonl"))?;
        let setup_failures = append_file(&root.join("setup-failures.jsonl"))?;
        let resources_path = root.join("resource-samples.csv");
        let resources_is_new = !resources_path.exists()
            || fs::metadata(&resources_path)
                .map(|metadata| metadata.len() == 0)
                .unwrap_or(true);
        let mut resources = append_file(&resources_path)?;
        if resources_is_new {
            writeln!(
                resources,
                "run_id,stack_id,sampled_at_unix_ms,service,container_id,cpu_percent,memory_bytes,memory_limit_bytes,network_rx_bytes,network_tx_bytes,block_read_bytes,block_write_bytes,pids"
            )?;
            resources.sync_data()?;
        }
        Ok(Self {
            root,
            trials,
            setup_failures,
            resources,
        })
    }

    pub fn resume(root: PathBuf) -> Result<(Self, RunManifest)> {
        repair_interrupted_jsonl(&root)?;
        let manifest: RunManifest = serde_json::from_slice(
            &fs::read(root.join("manifest.json")).context("read manifest for resume")?,
        )
        .context("parse manifest for resume")?;
        let store = Self::create(root, &manifest)?;
        Ok((store, manifest))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn append_trial(&mut self, trial: &TrialRecord) -> Result<()> {
        serde_json::to_writer(&mut self.trials, trial)?;
        writeln!(self.trials)?;
        self.trials.sync_data()?;
        let error = trial
            .error
            .as_deref()
            .unwrap_or("-")
            .chars()
            .map(|character| match character {
                '\r' | '\n' => ' ',
                other => other,
            })
            .collect::<String>();
        eprintln!(
            "[trial] stack={} profile={} op={:?} ring={}/{} {}={} concurrency={} status={} duration_ms={:.1} error_class={} error={}",
            trial.stack_id,
            trial.profile,
            trial.operation,
            trial.case.ring_size,
            trial.case.threshold,
            if trial.warmup { "warmup" } else { "trial" },
            trial.trial_index,
            trial
                .concurrency
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            if trial.success { "pass" } else { "fail" },
            trial.duration_ms,
            trial.error_class.as_deref().unwrap_or("-"),
            error,
        );
        Ok(())
    }

    pub fn append_setup_failure(&mut self, failure: &SetupFailureRecord) -> Result<()> {
        serde_json::to_writer(&mut self.setup_failures, failure)?;
        writeln!(self.setup_failures)?;
        self.setup_failures.sync_data()?;
        let error = failure
            .error
            .chars()
            .map(|character| match character {
                '\r' | '\n' => ' ',
                other => other,
            })
            .collect::<String>();
        eprintln!(
            "[setup-failure] stack={} profile={} network={} error_class={} error={}",
            failure.stack_id, failure.profile, failure.network_size, failure.error_class, error,
        );
        Ok(())
    }

    pub fn append_resource(&mut self, sample: &ResourceSample) -> Result<()> {
        writeln!(
            self.resources,
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_field(&sample.run_id),
            csv_field(&sample.stack_id),
            sample.sampled_at_unix_ms,
            csv_field(&sample.service),
            csv_field(&sample.container_id),
            option_value(sample.cpu_percent),
            option_value(sample.memory_bytes),
            option_value(sample.memory_limit_bytes),
            option_value(sample.network_rx_bytes),
            option_value(sample.network_tx_bytes),
            option_value(sample.block_read_bytes),
            option_value(sample.block_write_bytes),
            option_value(sample.pids),
        )?;
        Ok(())
    }

    pub fn update_manifest(&self, manifest: &RunManifest) -> Result<()> {
        write_json_atomic(&self.root.join("manifest.json"), manifest)
    }

    pub fn write_summary(&self) -> Result<Vec<SummaryRow>> {
        let trials = read_trials(&self.root)?;
        let mut rows = summarize(&trials);
        let manifest: RunManifest =
            serde_json::from_slice(&fs::read(self.root.join("manifest.json"))?)?;
        apply_expected_trial_counts(&mut rows, &manifest);
        let mut output = File::create(self.root.join("summary.csv"))?;
        writeln!(
            output,
            "profile,network_size,ring_size,threshold,operation,concurrency,trials,successes,viable,min_ms,median_ms,max_ms,p50_ms,p95_ms,p99_ms,throughput_per_sec,client_total_median_ms,verification_median_ms,acknowledgement_median_ms,scheduler_delay_median_ms"
        )?;
        for row in &rows {
            writeln!(
                output,
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                csv_field(&row.profile),
                row.network_size,
                row.ring_size,
                row.threshold,
                csv_field(&format!("{:?}", row.operation).to_lowercase()),
                option_value(row.concurrency),
                row.trials,
                row.successes,
                row.viable,
                option_value(row.min_ms),
                option_value(row.median_ms),
                option_value(row.max_ms),
                option_value(row.p50_ms),
                option_value(row.p95_ms),
                option_value(row.p99_ms),
                option_value(row.throughput_per_sec),
                option_value(row.client_total_median_ms),
                option_value(row.verification_median_ms),
                option_value(row.acknowledgement_median_ms),
                option_value(row.scheduler_delay_median_ms),
            )?;
        }
        output.sync_all()?;
        Ok(rows)
    }
}

fn repair_interrupted_jsonl(root: &Path) -> Result<()> {
    let path = root.join("trials.jsonl");
    if !path.exists() {
        return Ok(());
    }
    let bytes = fs::read(&path)?;
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        return Ok(());
    }
    let committed_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    fs::create_dir_all(root.join("logs"))?;
    fs::write(
        root.join("logs/interrupted-trial-fragment.bin"),
        &bytes[committed_len..],
    )?;
    OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(committed_len as u64)?;
    Ok(())
}

fn append_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {} for append", path.display()))
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(file)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

pub fn read_trials(root: &Path) -> Result<Vec<TrialRecord>> {
    let path = root.join("trials.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for (line_number, line) in BufReader::new(File::open(&path)?).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        records.push(
            serde_json::from_str(&line)
                .with_context(|| format!("parse {} line {}", path.display(), line_number + 1))?,
        );
    }
    Ok(records)
}

#[derive(Clone, Debug, Serialize)]
pub struct SummaryRow {
    pub profile: String,
    pub network_size: usize,
    pub ring_size: usize,
    pub threshold: usize,
    pub operation: Operation,
    pub concurrency: Option<usize>,
    pub trials: usize,
    pub successes: usize,
    pub viable: bool,
    pub min_ms: Option<f64>,
    pub median_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub throughput_per_sec: Option<f64>,
    pub client_total_median_ms: Option<f64>,
    pub verification_median_ms: Option<f64>,
    pub acknowledgement_median_ms: Option<f64>,
    pub scheduler_delay_median_ms: Option<f64>,
}

pub fn summarize(trials: &[TrialRecord]) -> Vec<SummaryRow> {
    type Key = (String, usize, usize, usize, Operation, Option<usize>);
    let mut groups: BTreeMap<Key, Vec<&TrialRecord>> = BTreeMap::new();
    for trial in trials.iter().filter(|trial| !trial.warmup) {
        groups
            .entry((
                trial.profile.clone(),
                trial.network_size,
                trial.case.ring_size,
                trial.case.threshold,
                trial.operation,
                trial.concurrency,
            ))
            .or_default()
            .push(trial);
    }
    groups
        .into_iter()
        .map(
            |((profile, network_size, ring_size, threshold, operation, concurrency), group)| {
                let successes = group.iter().filter(|trial| trial.success).count();
                let mut durations: Vec<f64> = group
                    .iter()
                    .filter(|trial| trial.success)
                    .map(|trial| trial.duration_ms)
                    .collect();
                durations.sort_by(f64::total_cmp);
                let throughput = mean(
                    &group
                        .iter()
                        .filter_map(|trial| trial.throughput_per_sec)
                        .collect::<Vec<_>>(),
                );
                let mut client_total: Vec<f64> = group
                    .iter()
                    .filter(|trial| trial.success)
                    .filter_map(|trial| trial.client_total_ms)
                    .collect();
                let mut verification: Vec<f64> = group
                    .iter()
                    .filter(|trial| trial.success)
                    .filter_map(|trial| trial.verification_ms)
                    .collect();
                let mut acknowledgement: Vec<f64> = group
                    .iter()
                    .filter(|trial| trial.success)
                    .filter_map(|trial| trial.acknowledgement_ms)
                    .collect();
                let mut scheduler_delay: Vec<f64> = group
                    .iter()
                    .filter(|trial| trial.success)
                    .filter_map(|trial| trial.scheduler_delay_ms)
                    .collect();
                SummaryRow {
                    profile,
                    network_size,
                    ring_size,
                    threshold,
                    operation,
                    concurrency,
                    trials: group.len(),
                    successes,
                    viable: successes == group.len() && !group.is_empty(),
                    min_ms: durations.first().copied(),
                    median_ms: percentile_sorted(&durations, 0.5),
                    max_ms: durations.last().copied(),
                    p50_ms: mean(
                        &group
                            .iter()
                            .filter_map(|trial| trial.latency_p50_ms)
                            .collect::<Vec<_>>(),
                    ),
                    p95_ms: mean(
                        &group
                            .iter()
                            .filter_map(|trial| trial.latency_p95_ms)
                            .collect::<Vec<_>>(),
                    ),
                    p99_ms: mean(
                        &group
                            .iter()
                            .filter_map(|trial| trial.latency_p99_ms)
                            .collect::<Vec<_>>(),
                    ),
                    throughput_per_sec: throughput,
                    client_total_median_ms: percentile(&mut client_total, 0.5),
                    verification_median_ms: percentile(&mut verification, 0.5),
                    acknowledgement_median_ms: percentile(&mut acknowledgement, 0.5),
                    scheduler_delay_median_ms: percentile(&mut scheduler_delay, 0.5),
                }
            },
        )
        .collect()
}

/// Narrow each row's viability to also require every expected repetition (or,
/// for a load trial, its one fixed-window run) actually completed — a trial
/// that never ran at all must not still read as viable.
pub fn apply_expected_trial_counts(rows: &mut [SummaryRow], manifest: &RunManifest) {
    for row in rows {
        let expected = if row.concurrency.is_some() {
            1
        } else {
            manifest.experiment.repetitions
        };
        row.viable &= row.trials == expected;
    }
}

pub fn percentile(values: &mut [f64], quantile: f64) -> Option<f64> {
    values.sort_by(f64::total_cmp);
    percentile_sorted(values, quantile)
}

fn percentile_sorted(values: &[f64], quantile: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let q = quantile.clamp(0.0, 1.0);
    let position = q * (values.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        Some(values[lower])
    } else {
        let fraction = position - lower as f64;
        Some(values[lower] * (1.0 - fraction) + values[upper] * fraction)
    }
}

fn mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn option_value<T: ToString>(value: Option<T>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

pub fn crypto_label(crypto: CryptoFeature) -> &'static str {
    crypto.feature_name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Experiment;

    #[test]
    fn percentile_interpolates_and_handles_empty_input() {
        let mut values = vec![1.0, 4.0, 2.0, 3.0];
        assert_eq!(percentile(&mut values, 0.5), Some(2.5));
        assert_eq!(percentile(&mut [], 0.5), None);
    }

    #[test]
    fn all_measured_trials_must_pass_for_viability() {
        let base = TrialRecord {
            run_id: "r".into(),
            stack_id: "s".into(),
            profile: "lan".into(),
            network_size: 3,
            case: RingCase {
                ring_size: 3,
                threshold: 2,
            },
            operation: Operation::Dkg,
            trial_index: 0,
            warmup: false,
            concurrency: None,
            started_at_unix_ms: 0,
            duration_ms: 10.0,
            client_total_ms: None,
            acknowledgement_ms: None,
            verification_ms: None,
            scheduler_delay_ms: None,
            throughput_per_sec: None,
            successful_requests: None,
            failed_requests: None,
            latency_p50_ms: None,
            latency_p95_ms: None,
            latency_p99_ms: None,
            success: true,
            error_class: None,
            error: None,
            ring_id: None,
            ring_pk: None,
            metric_deltas: BTreeMap::new(),
        };
        let mut failed = base.clone();
        failed.trial_index = 1;
        failed.success = false;
        let rows = summarize(&[base, failed]);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].viable);
    }

    #[test]
    fn resume_preserves_committed_trials_and_quarantines_partial_tail() {
        let root = std::env::temp_dir().join(format!(
            "orbis-bench-resume-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let experiment = Experiment::single(3, 3, 2);
        let manifest = RunManifest {
            schema_version: 1,
            run_id: "resume-test".into(),
            created_at_unix_ms: 1,
            completed_at_unix_ms: None,
            status: RunStatus::Interrupted,
            vera_ref: experiment.vera_ref.clone(),
            experiment,
            host: HostMetadata {
                os: "test".into(),
                architecture: "test".into(),
                cpu_count: 1,
                cpu_model: None,
                host_memory_bytes: None,
                disk_available_bytes: None,
                git_commit: None,
                git_dirty: None,
                docker_version: None,
                docker_info: None,
            },
            node_image: None,
            vera_image: None,
            crypto_implementation: "bls12-381".into(),
            stack_projects: Vec::new(),
            profile_calibration: BTreeMap::new(),
            setup_batch_evidence: BTreeMap::new(),
            warnings: Vec::new(),
        };
        let mut store = ResultStore::create(root.clone(), &manifest).unwrap();
        let trial = TrialRecord {
            run_id: "resume-test".into(),
            stack_id: "orbis-bench-resume-s000".into(),
            profile: "lan".into(),
            network_size: 3,
            case: RingCase {
                ring_size: 3,
                threshold: 2,
            },
            operation: Operation::Dkg,
            trial_index: 0,
            warmup: false,
            concurrency: None,
            started_at_unix_ms: 1,
            duration_ms: 1.0,
            client_total_ms: None,
            acknowledgement_ms: None,
            verification_ms: None,
            scheduler_delay_ms: None,
            throughput_per_sec: None,
            successful_requests: None,
            failed_requests: None,
            latency_p50_ms: None,
            latency_p95_ms: None,
            latency_p99_ms: None,
            success: true,
            error_class: None,
            error: None,
            ring_id: None,
            ring_pk: None,
            metric_deltas: BTreeMap::new(),
        };
        store.append_trial(&trial).unwrap();
        drop(store);
        let mut file = OpenOptions::new()
            .append(true)
            .open(root.join("trials.jsonl"))
            .unwrap();
        write!(file, "{{\"partial\":").unwrap();
        drop(file);

        let (resumed_store, resumed) = ResultStore::resume(root.clone()).unwrap();
        assert_eq!(resumed.run_id, "resume-test");
        assert_eq!(read_trials(&root).unwrap().len(), 1);
        assert!(root.join("logs/interrupted-trial-fragment.bin").is_file());
        drop(resumed_store);
        fs::remove_dir_all(root).unwrap();
    }
}
