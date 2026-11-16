//! Deterministic Hub/native startup used by integration fixtures.

use super::startup::NativeStartupPolicy;

pub struct FixtureNativeStartup;

impl NativeStartupPolicy for FixtureNativeStartup {
    fn initial_signing_key() -> Option<String> {
        std::env::var("ORBIS_SIGNING_KEY").ok()
    }
}
