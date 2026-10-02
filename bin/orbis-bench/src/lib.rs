pub mod compose;
pub mod config;
pub mod docker;
pub mod harness;
pub mod metrics;
pub mod protocol;
pub mod report;
pub mod results;
pub mod runner;
pub mod setup;
pub mod upgrade;

pub use config::{Experiment, ExperimentPlan};
pub use runner::BenchmarkRunner;

#[cfg(all(feature = "bls12-381", feature = "jubjub"))]
compile_error!("Features 'bls12-381' and 'jubjub' are mutually exclusive");

#[cfg(not(any(feature = "bls12-381", feature = "jubjub")))]
compile_error!("One crypto feature must be enabled");
