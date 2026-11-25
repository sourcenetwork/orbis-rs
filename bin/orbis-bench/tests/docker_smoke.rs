use orbis_bench::config::{Experiment, NetworkProfile, Operation};
use orbis_bench::results::read_trials;
use orbis_bench::runner::{BenchmarkRunner, RunOptions};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn smoke_experiment(profile: NetworkProfile, network_size: usize, ring_size: usize) -> Experiment {
    let mut experiment = Experiment::single(network_size, ring_size, (2 * ring_size).div_ceil(3));
    experiment.name = format!("docker-smoke-{network_size}-{ring_size}-{}", profile.name);
    experiment.profiles = vec![profile];
    experiment.warmups = 0;
    experiment.repetitions = 1;
    experiment.load.warmup_secs = 1;
    experiment.load.measure_secs = 1;
    experiment.load.concurrency = vec![1];
    // All tests in this file share one process, so the PID alone is not
    // enough to keep their output directories from colliding when run
    // together (e.g. via `cargo test -- --ignored`).
    experiment.output_dir = PathBuf::from(format!(
        "/tmp/orbis-bench-smoke-{}-{}",
        std::process::id(),
        experiment.name
    ));
    experiment
}

#[tokio::test]
#[ignore = "builds production Docker images and runs DKG, PRE, SIGN, and PSS"]
async fn three_node_lan_core_operations() {
    let experiment = smoke_experiment(NetworkProfile::lan(), 3, 3);
    let run_dir = BenchmarkRunner::new(experiment, RunOptions::default())
        .unwrap()
        .run()
        .await
        .unwrap();
    assert_core_smoke_passed(&run_dir);
}

#[tokio::test]
#[ignore = "requires Docker NET_ADMIN and runs a shaped production stack"]
async fn three_node_shaped_wan_core_operations() {
    let experiment = smoke_experiment(NetworkProfile::wan_50ms(), 3, 3);
    let run_dir = BenchmarkRunner::new(experiment, RunOptions::default())
        .unwrap()
        .run()
        .await
        .unwrap();
    assert_core_smoke_passed(&run_dir);
}

#[tokio::test]
#[ignore = "builds production Docker images and runs a 2-to-2 reshare over a 3-node union"]
async fn three_node_lan_reshare() {
    let mut experiment = smoke_experiment(NetworkProfile::lan(), 3, 2);
    experiment.name = "docker-smoke-3-node-reshare".into();
    experiment.operations = BTreeSet::from([Operation::PssReshare]);
    experiment.reshare_overlap = Some(1);
    let run_dir = BenchmarkRunner::new(experiment, RunOptions::default())
        .unwrap()
        .run()
        .await
        .unwrap();

    let trials = read_trials(&run_dir).expect("read reshare smoke evidence");
    assert_eq!(trials.len(), 1);
    assert_eq!(trials[0].operation, Operation::PssReshare);
    assert!(
        trials[0].success,
        "reshare smoke failed: {:?}; inspect {}",
        trials[0].error,
        run_dir.display()
    );
    assert_preparation_transport_evidence(&trials, 3);
}

fn assert_core_smoke_passed(run_dir: &std::path::Path) {
    let trials = read_trials(run_dir).expect("read smoke evidence");
    assert_eq!(
        trials.len(),
        6,
        "four serial operations plus two load stages"
    );
    assert!(
        trials.iter().all(|trial| trial.success),
        "smoke produced failed trials: {:?}",
        trials
            .iter()
            .filter(|trial| !trial.success)
            .map(|trial| (&trial.operation, &trial.error))
            .collect::<Vec<_>>()
    );
}

fn transport_event_delta(trial: &orbis_bench::results::TrialRecord, event: &str) -> f64 {
    let event_label = format!("event=\"{event}\"");
    trial
        .metric_deltas
        .iter()
        .filter(|(key, _)| {
            key.starts_with("dkg_transport_events_total{") && key.contains(&event_label)
        })
        .map(|(_, value)| value)
        .sum()
}

fn assert_preparation_transport_evidence<'a>(
    trials: impl IntoIterator<Item = &'a orbis_bench::results::TrialRecord>,
    expected_acknowledgements: usize,
) {
    for trial in trials {
        assert_eq!(
            transport_event_delta(trial, "probe_ack"),
            expected_acknowledgements as f64,
            "each successful preparation must record every committee member exactly once"
        );

        let rejoins = [
            "rejoin_isolation",
            "rejoin_lag",
            "rejoin_subscription_error",
        ]
        .into_iter()
        .map(|event| transport_event_delta(trial, event))
        .sum::<f64>();
        assert!(
            rejoins <= expected_acknowledgements as f64,
            "preparation caused a Gossip rejoin storm: {rejoins} rejoins for {expected_acknowledgements} members"
        );
    }
}

#[tokio::test]
#[ignore = "50-node LAN preparation gate; one warm-up plus ten measured 7-of-8 DKG trials"]
async fn fifty_node_ring_eight_preparation_acceptance_lan() {
    let mut experiment = smoke_experiment(NetworkProfile::lan(), 50, 8);
    experiment.name = "transport-50-node-ring-8-threshold-7-preparation".into();
    experiment.networks[0].cases[0].threshold = 7;
    experiment.warmups = 1;
    experiment.repetitions = 10;
    experiment.operations = BTreeSet::from([Operation::Dkg]);
    let run_dir = BenchmarkRunner::new(experiment, RunOptions::default())
        .unwrap()
        .run()
        .await
        .unwrap();

    let trials = read_trials(&run_dir).expect("read 7-of-8 acceptance evidence");
    let measured = trials
        .iter()
        .filter(|trial| !trial.warmup)
        .collect::<Vec<_>>();
    assert_eq!(measured.len(), 10, "ten measured DKG trials are required");
    assert!(
        measured.iter().all(|trial| trial.success),
        "7-of-8 preparation acceptance produced failures; inspect {}",
        run_dir.display()
    );
    assert_preparation_transport_evidence(measured, 8);
}

#[tokio::test]
#[ignore = "50-node LAN/WAN transport acceptance; intentionally resource intensive"]
async fn fifty_node_transport_acceptance_lan_and_wan() {
    let mut experiment = smoke_experiment(NetworkProfile::lan(), 50, 50);
    experiment.name = "transport-50-node-34-threshold-acceptance".into();
    experiment.profiles = vec![NetworkProfile::lan(), NetworkProfile::wan_50ms()];
    experiment.warmups = 1;
    experiment.repetitions = 5;
    experiment.operations = BTreeSet::from([Operation::Dkg, Operation::PssRefresh]);
    let run_dir = BenchmarkRunner::new(experiment, RunOptions::default())
        .unwrap()
        .run()
        .await
        .unwrap();
    assert!(run_dir.join("manifest.json").is_file());
    assert!(run_dir.join("trials.jsonl").is_file());
    assert!(run_dir.join("report.html").is_file());

    let trials = read_trials(&run_dir).expect("read 50-node acceptance evidence");
    let measured = trials
        .iter()
        .filter(|trial| !trial.warmup)
        .collect::<Vec<_>>();
    assert_eq!(
        measured.len(),
        20,
        "five DKG and five refresh trials are required for each of LAN and WAN"
    );
    assert!(
        measured.iter().all(|trial| trial.success),
        "50-node transport acceptance produced failures; inspect {}",
        run_dir.display()
    );
    assert_preparation_transport_evidence(measured, 50);
}

#[tokio::test]
#[ignore = "50-node old/new-union reshare acceptance; intentionally resource intensive"]
async fn fifty_node_reshare_acceptance_lan_and_wan() {
    let mut experiment = smoke_experiment(NetworkProfile::lan(), 50, 34);
    experiment.name = "reshare-50-node-34-member-threshold-23-overlap-18".into();
    experiment.profiles = vec![NetworkProfile::lan(), NetworkProfile::wan_50ms()];
    experiment.warmups = 1;
    experiment.repetitions = 5;
    experiment.operations = BTreeSet::from([Operation::PssReshare]);
    experiment.reshare_overlap = Some(18);
    // Fifty schedulers polling Vera every second can saturate Docker
    // Desktop's bridge while the initial all-member DKG is exchanging UDP.
    // Ten seconds still exercises production scheduling while keeping the
    // chain-control plane available to finalize the ceremony.
    experiment.pss_poll_interval_secs = 10;

    let run_dir = BenchmarkRunner::new(experiment, RunOptions::default())
        .unwrap()
        .run()
        .await
        .unwrap();
    assert!(run_dir.join("manifest.json").is_file());
    assert!(run_dir.join("trials.jsonl").is_file());
    assert!(run_dir.join("report.html").is_file());

    let trials = read_trials(&run_dir).expect("read 50-node reshare acceptance evidence");
    let measured = trials
        .iter()
        .filter(|trial| !trial.warmup)
        .collect::<Vec<_>>();
    assert_eq!(
        measured.len(),
        10,
        "five reshares are required for each of LAN and WAN"
    );
    assert!(
        measured.iter().all(|trial| trial.success),
        "50-node reshare acceptance produced failures; inspect {}",
        run_dir.display()
    );
    assert_preparation_transport_evidence(measured, 50);
}
