#![cfg(feature = "orbis-node")]

pub mod config;
pub mod harness;
pub mod protocol;
pub mod report;
pub mod results;
pub mod runner;

pub use config::{Experiment, ExperimentPlan};
pub use runner::BenchmarkRunner;

#[cfg(all(feature = "bls12-381", feature = "jubjub"))]
compile_error!("Features 'bls12-381' and 'jubjub' are mutually exclusive");

#[cfg(not(any(feature = "bls12-381", feature = "jubjub")))]
compile_error!("One crypto feature must be enabled");
