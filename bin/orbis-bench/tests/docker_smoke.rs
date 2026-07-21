use orbis_bench::config::{Experiment, NetworkProfile, Operation};
use orbis_bench::results::read_trials;
use orbis_bench::runner::{BenchmarkRunner, RunOptions};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn smoke_experiment(profile: NetworkProfile, network_size: usize, ring_size: usize) -> Experiment {
    let mut experiment = Experiment::single(network_size, ring_size, (2 * ring_size).div_ceil(3));
    experiment.name = format!("docker-smoke-{network_size}-{ring_size}");
    experiment.profiles = vec![profile];
    experiment.warmups = 0;
    experiment.repetitions = 1;
    experiment.load.warmup_secs = 1;
    experiment.load.measure_secs = 1;
    experiment.load.concurrency = vec![1];
    experiment.output_dir = PathBuf::from(format!("/tmp/orbis-bench-smoke-{}", std::process::id()));
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

#[tokio::test]
#[ignore = "50-node acceptance run; intentionally resource intensive"]
async fn fifty_node_acceptance_always_preserves_a_report() {
    let mut experiment = smoke_experiment(NetworkProfile::lan(), 50, 50);
    experiment.operations = BTreeSet::from([
        Operation::Dkg,
        Operation::Pre,
        Operation::Sign,
        Operation::PssRefresh,
    ]);
    let run_dir = BenchmarkRunner::new(experiment, RunOptions::default())
        .unwrap()
        .run()
        .await
        .unwrap();
    assert!(run_dir.join("manifest.json").is_file());
    assert!(run_dir.join("trials.jsonl").is_file());
    assert!(run_dir.join("report.html").is_file());
}
