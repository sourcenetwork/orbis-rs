use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use orbis_bench::config::{Experiment, NetworkGroup, RingCase};
use orbis_bench::docker::{doctor, DockerCompose};
use orbis_bench::report::generate_report;
use orbis_bench::results::RunManifest;
use orbis_bench::runner::{BenchmarkRunner, RunOptions};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "orbis-bench",
    version,
    about = "Local Orbis network benchmark and capacity tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate Docker, host allocation, shaping support, and runtime image contents.
    Doctor {
        /// Existing benchmark runtime image to probe for tc and packaging isolation.
        #[arg(long)]
        runtime_image: Option<String>,
    },
    /// Resolve and validate an experiment without starting containers.
    Plan(ExperimentArgs),
    /// Run one case or all cases in an experiment YAML file.
    Run(RunArgs),
    /// Run a listed or generated capacity sweep.
    Sweep(SweepArgs),
    /// Regenerate the self-contained report from raw evidence.
    Report { run_dir: PathBuf },
    /// Remove only Compose projects recorded by a benchmark run.
    Cleanup { run_dir: PathBuf },
}

#[derive(Args, Clone)]
struct ExperimentArgs {
    /// Versioned experiment YAML file.
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, requires_all = ["ring_size", "threshold"])]
    network_size: Option<usize>,
    #[arg(long, requires_all = ["network_size", "threshold"])]
    ring_size: Option<usize>,
    #[arg(long, requires_all = ["network_size", "ring_size"])]
    threshold: Option<usize>,
    /// Override raw artifact directory for flag-defined experiments.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct RunArgs {
    #[command(flatten)]
    experiment: ExperimentArgs,
    /// Resume the experiment recorded in this run directory.
    #[arg(long)]
    resume: Option<PathBuf>,
    /// Leave the uniquely named Compose stack running for debugging.
    #[arg(long)]
    keep_network: bool,
}

#[derive(Args)]
struct SweepArgs {
    /// Versioned experiment YAML. Its explicit cases are used as the sweep.
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, required_unless_present_any = ["config", "resume"])]
    network_size: Option<usize>,
    /// Comma-delimited explicit ring sizes, e.g. 3,5,10,20.
    #[arg(long, conflicts_with_all = ["ring_start", "ring_max"])]
    ring_sizes: Option<String>,
    #[arg(long, requires = "ring_max")]
    ring_start: Option<usize>,
    #[arg(long, requires = "ring_start")]
    ring_max: Option<usize>,
    #[arg(long, default_value_t = 1)]
    ring_step: usize,
    /// Comma-delimited thresholds aligned with --ring-sizes. Defaults to ceil(2n/3).
    #[arg(long)]
    thresholds: Option<String>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    resume: Option<PathBuf>,
    #[arg(long)]
    keep_network: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Doctor { runtime_image } => {
            let report = doctor(runtime_image.as_deref()).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Plan(args) => {
            let experiment = resolve_experiment(&args)?;
            let mut plan = experiment.resolve()?;
            plan.assign_indices();
            println!("{}", serde_yaml::to_string(&plan)?);
            println!("artifacts: {}", experiment.output_dir.display());
        }
        Command::Run(args) => {
            let experiment = if let Some(resume) = &args.resume {
                read_manifest(resume)?.experiment
            } else {
                resolve_experiment(&args.experiment)?
            };
            let output = BenchmarkRunner::new(
                experiment,
                RunOptions {
                    resume: args.resume,
                    keep_network: args.keep_network,
                    stop_after_two_non_viable_sizes: false,
                },
            )?
            .run()
            .await?;
            println!("benchmark evidence: {}", output.display());
        }
        Command::Sweep(args) => {
            let experiment = resolve_sweep(&args)?;
            let output = BenchmarkRunner::new(
                experiment,
                RunOptions {
                    resume: args.resume,
                    keep_network: args.keep_network,
                    stop_after_two_non_viable_sizes: true,
                },
            )?
            .run()
            .await?;
            println!("benchmark evidence: {}", output.display());
        }
        Command::Report { run_dir } => {
            generate_report(&run_dir)?;
            println!("report: {}", run_dir.join("report.html").display());
        }
        Command::Cleanup { run_dir } => cleanup(&run_dir).await?,
    }
    Ok(())
}

fn resolve_experiment(args: &ExperimentArgs) -> Result<Experiment> {
    if let Some(config) = &args.config {
        if args.network_size.is_some() || args.ring_size.is_some() || args.threshold.is_some() {
            bail!("--config cannot be combined with individual case flags");
        }
        return Experiment::from_yaml(config);
    }
    let mut experiment = Experiment::single(
        args.network_size
            .context("provide --config or --network-size")?,
        args.ring_size.context("provide --config or --ring-size")?,
        args.threshold.context("provide --config or --threshold")?,
    );
    if let Some(output) = &args.output {
        experiment.output_dir = output.clone();
    }
    experiment.validate()?;
    Ok(experiment)
}

fn resolve_sweep(args: &SweepArgs) -> Result<Experiment> {
    if let Some(resume) = &args.resume {
        return Ok(read_manifest(resume)?.experiment);
    }
    if let Some(config) = &args.config {
        return Experiment::from_yaml(config);
    }
    if args.ring_step == 0 {
        bail!("--ring-step must be at least one");
    }
    let network_size = args.network_size.context("--network-size is required")?;
    let sizes = if let Some(sizes) = &args.ring_sizes {
        parse_usize_list(sizes, "ring size")?
    } else if let (Some(start), Some(maximum)) = (args.ring_start, args.ring_max) {
        if start > maximum {
            bail!("--ring-start cannot exceed --ring-max");
        }
        (start..=maximum).step_by(args.ring_step).collect()
    } else {
        bail!("provide --ring-sizes or --ring-start with --ring-max");
    };
    let thresholds = args
        .thresholds
        .as_deref()
        .map(|value| parse_usize_list(value, "threshold"))
        .transpose()?;
    if thresholds
        .as_ref()
        .is_some_and(|values| values.len() != sizes.len())
    {
        bail!("--thresholds must contain one value for every ring size");
    }
    let cases: Vec<RingCase> = sizes
        .iter()
        .enumerate()
        .map(|(index, &ring_size)| RingCase {
            ring_size,
            threshold: thresholds
                .as_ref()
                .map(|values| values[index])
                .unwrap_or_else(|| (2 * ring_size).div_ceil(3)),
        })
        .collect();
    let first = cases
        .first()
        .context("sweep contains no ring sizes")?
        .clone();
    let mut experiment = Experiment::single(network_size, first.ring_size, first.threshold);
    experiment.name = format!("orbis-capacity-{network_size}n");
    // One group per size allows an advancing sweep to stop before provisioning
    // later sizes while retaining separate LAN and WAN stacks.
    experiment.networks = cases
        .into_iter()
        .map(|case| NetworkGroup {
            network_size,
            cases: vec![case],
        })
        .collect();
    if let Some(output) = &args.output {
        experiment.output_dir = output.clone();
    }
    experiment.validate()?;
    Ok(experiment)
}

fn parse_usize_list(input: &str, label: &str) -> Result<Vec<usize>> {
    input
        .split(',')
        .map(|value| {
            value
                .trim()
                .parse()
                .with_context(|| format!("invalid {label} {value:?}"))
        })
        .collect()
}

fn read_manifest(run_dir: &Path) -> Result<RunManifest> {
    Ok(serde_json::from_slice(&fs::read(
        run_dir.join("manifest.json"),
    )?)?)
}

async fn cleanup(run_dir: &Path) -> Result<()> {
    let manifest = read_manifest(run_dir)?;
    for project in &manifest.stack_projects {
        let compose_file = run_dir.join("stacks").join(project).join("compose.yaml");
        if !compose_file.exists() {
            eprintln!("skip {project}: resolved compose file is missing");
            continue;
        }
        let compose = DockerCompose::new(project.clone(), compose_file)?;
        compose.down().await?;
        println!("removed exact Compose project {project}");
    }
    Ok(())
}
