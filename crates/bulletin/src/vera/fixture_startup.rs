//! Deterministic Vera startup used by integration fixtures.

use super::startup::VeraStartupPolicy;

pub struct FixtureVeraStartup;

impl VeraStartupPolicy for FixtureVeraStartup {
    fn initial_signing_key() -> Option<String> {
        std::env::var("ORBIS_SIGNING_KEY").ok()
    }
}
