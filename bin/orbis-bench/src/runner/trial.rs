//! Backend-agnostic trial plumbing shared by the Docker (`docker.rs`) and
//! in-process (`in_process.rs`) backends: the context bundle threaded through
//! every trial call, trial identity/dedup, `TrialRecord` construction, and the
//! load-generation helpers (already backend-agnostic — plain gRPC calls against
//! `DirectClients`).

use super::*;

/// Data shared by every trial call within one stack's run — what used to be
/// repeated as a long, ad hoc parameter list on `run_case` and each
/// `run_*_trials(_in_process)` method. Constructed once per stack (right after
/// `clients`/`rng` are set up, in `docker::run_stack_docker` /
/// `in_process::run_stack_in_process`), then threaded as `&mut TrialContext`
/// into every trial call for that stack. Backend-specific data
/// (compose/controller/endpoints for Docker, harness for in-process) and
/// case-specific data (the case/ring/fixture being measured) stay as separate
/// parameters — only what's identical on every call lives here.
pub(super) struct TrialContext<'a> {
    pub(super) store: &'a mut ResultStore,
    pub(super) manifest: &'a RunManifest,
    pub(super) stack: &'a StackPlan,
    pub(super) stack_id: &'a str,
    pub(super) clients: &'a mut DirectClients,
    pub(super) completed: &'a HashSet<TrialKey>,
    pub(super) rng: &'a mut StdRng,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct TrialKey {
    pub(super) stack_id: String,
    pub(super) profile: String,
    pub(super) ring_size: usize,
    pub(super) threshold: usize,
    pub(super) operation: Operation,
    pub(super) trial_index: usize,
    pub(super) warmup: bool,
    pub(super) concurrency: Option<usize>,
}

impl TrialKey {
    pub(super) fn serial(
        stack: &str,
        profile: &str,
        case: &RingCase,
        operation: Operation,
        trial_index: usize,
        warmup: bool,
    ) -> Self {
        Self {
            stack_id: stack.into(),
            profile: profile.into(),
            ring_size: case.ring_size,
            threshold: case.threshold,
            operation,
            trial_index,
            warmup,
            concurrency: None,
        }
    }
    pub(super) fn load(
        stack: &str,
        profile: &str,
        case: &RingCase,
        operation: Operation,
        concurrency: usize,
    ) -> Self {
        Self {
            stack_id: stack.into(),
            profile: profile.into(),
            ring_size: case.ring_size,
            threshold: case.threshold,
            operation,
            trial_index: 0,
            warmup: false,
            concurrency: Some(concurrency),
        }
    }
}

pub(super) fn completed_trial_keys(root: &Path) -> Result<HashSet<TrialKey>> {
    Ok(read_trials(root)?
        .into_iter()
        .map(|trial| TrialKey {
            stack_id: trial.stack_id,
            profile: trial.profile,
            ring_size: trial.case.ring_size,
            threshold: trial.case.threshold,
            operation: trial.operation,
            trial_index: trial.trial_index,
            warmup: trial.warmup,
            concurrency: trial.concurrency,
        })
        .collect())
}

pub(super) struct OnlineFixtures {
    pub(super) pre: PreFixture,
    pub(super) sign: SignFixture,
}

#[derive(Clone, Debug, Default)]
pub(super) struct LoadMeasurement {
    pub(super) duration_ms: f64,
    pub(super) successes: u64,
    pub(super) failures: u64,
    pub(super) latencies: Vec<f64>,
}

pub(super) async fn run_pre_load(
    client: proto::v0::pre::pre_service_client::PreServiceClient<tonic::transport::Channel>,
    fixture: PreFixture,
    concurrency: usize,
    duration: Duration,
) -> LoadMeasurement {
    let deadline = Instant::now() + duration;
    let started = Instant::now();
    let tasks = (0..concurrency).map(|_| {
        let mut client = client.clone();
        let fixture = fixture.clone();
        tokio::spawn(async move {
            let mut result = LoadMeasurement::default();
            while Instant::now() < deadline {
                match crate::protocol::pre_call(&mut client, &fixture).await {
                    Ok(measurement) => {
                        result.successes += 1;
                        result.latencies.push(measurement.total_ms);
                    }
                    Err(_) => result.failures += 1,
                }
            }
            result
        })
    });
    combine_load(join_all(tasks).await, started.elapsed())
}

pub(super) async fn run_sign_load(
    client: proto::v0::sign::sign_service_client::SignServiceClient<tonic::transport::Channel>,
    fixture: SignFixture,
    concurrency: usize,
    duration: Duration,
) -> LoadMeasurement {
    let deadline = Instant::now() + duration;
    let started = Instant::now();
    let tasks = (0..concurrency).map(|worker| {
        let mut client = client.clone();
        let fixture = fixture.clone();
        tokio::spawn(async move {
            let mut result = LoadMeasurement::default();
            let mut sequence = 0u64;
            while Instant::now() < deadline {
                let message = format!("orbis-bench-load-{worker}-{sequence}").into_bytes();
                sequence += 1;
                match sign_call(&mut client, &fixture, message).await {
                    Ok(measurement) => {
                        result.successes += 1;
                        result.latencies.push(measurement.total_ms);
                    }
                    Err(_) => result.failures += 1,
                }
            }
            result
        })
    });
    combine_load(join_all(tasks).await, started.elapsed())
}

fn combine_load(
    results: Vec<std::result::Result<LoadMeasurement, tokio::task::JoinError>>,
    duration: Duration,
) -> LoadMeasurement {
    let mut combined = LoadMeasurement {
        duration_ms: duration.as_secs_f64() * 1000.0,
        ..LoadMeasurement::default()
    };
    for result in results {
        match result {
            Ok(result) => {
                combined.successes += result.successes;
                combined.failures += result.failures;
                combined.latencies.extend(result.latencies);
            }
            Err(_) => combined.failures += 1,
        }
    }
    combined
}

/// Same shape as the Docker-backend's `docker::base_trial`, but takes `case`/
/// `ring_id` directly since the in-process trial loops don't build a
/// `CaseRings`/`PlannedRing` (there's no chain-assigned `RingDefinition` to
/// wrap — see `in_process::run_dkg_trials_in_process`).
#[allow(clippy::too_many_arguments)]
pub(super) fn base_trial_in_process(
    manifest: &RunManifest,
    stack: &StackPlan,
    stack_id: &str,
    case: &RingCase,
    ring_id: &str,
    operation: Operation,
    trial_index: usize,
    warmup: bool,
    duration_ms: f64,
    verification_ms: Option<f64>,
    success: bool,
    error_class: Option<String>,
    error: Option<String>,
) -> TrialRecord {
    TrialRecord {
        run_id: manifest.run_id.clone(),
        stack_id: stack_id.into(),
        profile: stack.profile.name.clone(),
        network_size: stack.network_size,
        case: case.clone(),
        operation,
        trial_index,
        warmup,
        concurrency: None,
        started_at_unix_ms: unix_ms(),
        duration_ms,
        client_total_ms: None,
        acknowledgement_ms: None,
        verification_ms,
        scheduler_delay_ms: None,
        throughput_per_sec: None,
        successful_requests: None,
        failed_requests: None,
        latency_p50_ms: None,
        latency_p95_ms: None,
        latency_p99_ms: None,
        success,
        error_class,
        error,
        ring_id: Some(ring_id.to_string()),
        ring_pk: None,
        metric_deltas: BTreeMap::new(),
    }
}

/// In-process counterpart of `docker::load_trial` — see `base_trial_in_process`.
pub(super) fn load_trial_in_process(
    manifest: &RunManifest,
    stack: &StackPlan,
    stack_id: &str,
    case: &RingCase,
    ring_id: &str,
    operation: Operation,
    concurrency: usize,
    mut measurement: LoadMeasurement,
) -> TrialRecord {
    measurement.latencies.sort_by(f64::total_cmp);
    let total = measurement.successes + measurement.failures;
    TrialRecord {
        run_id: manifest.run_id.clone(),
        stack_id: stack_id.into(),
        profile: stack.profile.name.clone(),
        network_size: stack.network_size,
        case: case.clone(),
        operation,
        trial_index: 0,
        warmup: false,
        concurrency: Some(concurrency),
        started_at_unix_ms: unix_ms(),
        duration_ms: measurement.duration_ms,
        client_total_ms: None,
        acknowledgement_ms: None,
        verification_ms: None,
        scheduler_delay_ms: None,
        throughput_per_sec: Some(measurement.successes as f64 / (measurement.duration_ms / 1000.0)),
        successful_requests: Some(measurement.successes),
        failed_requests: Some(measurement.failures),
        latency_p50_ms: percentile_sorted(&measurement.latencies, 0.50),
        latency_p95_ms: percentile_sorted(&measurement.latencies, 0.95),
        latency_p99_ms: percentile_sorted(&measurement.latencies, 0.99),
        success: measurement.failures == 0 && total > 0,
        error_class: (measurement.failures > 0).then(|| "load_request_failures".into()),
        error: (measurement.failures > 0)
            .then(|| format!("{} of {total} requests failed", measurement.failures)),
        ring_id: Some(ring_id.to_string()),
        ring_pk: None,
        metric_deltas: BTreeMap::new(),
    }
}

pub(super) fn percentile_sorted(values: &[f64], quantile: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let position = quantile * (values.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    Some(if lower == upper {
        values[lower]
    } else {
        values[lower] * (upper as f64 - position) + values[upper] * (position - lower as f64)
    })
}

pub(super) fn pss_timing(
    due_to_completion_ms: f64,
    observed_scheduler_delay_ms: f64,
    metric_scheduler_delay_ms: Option<f64>,
) -> (f64, f64) {
    let valid_delay =
        |delay: f64| delay.is_finite() && delay >= 0.0 && delay < due_to_completion_ms;
    let scheduler_delay_ms = metric_scheduler_delay_ms
        .filter(|delay| valid_delay(*delay))
        .or_else(|| valid_delay(observed_scheduler_delay_ms).then_some(observed_scheduler_delay_ms))
        .unwrap_or(0.0);
    (
        due_to_completion_ms - scheduler_delay_ms,
        scheduler_delay_ms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolated_percentile_is_reported() {
        assert_eq!(percentile_sorted(&[1.0, 2.0, 3.0], 0.5), Some(2.0));
    }

    #[test]
    fn pss_timing_rejects_scheduler_delay_larger_than_observed_wait() {
        assert_eq!(pss_timing(500.0, 0.0, Some(600.0)), (500.0, 0.0));
    }

    #[test]
    fn pss_timing_separates_a_valid_scheduler_delay() {
        assert_eq!(pss_timing(1_500.0, 0.0, Some(400.0)), (1_100.0, 400.0));
    }
}
