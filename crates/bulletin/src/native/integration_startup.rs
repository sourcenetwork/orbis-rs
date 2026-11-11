use super::startup::NativeStartupPolicy;

pub struct IntegrationTestNativeStartup;

impl NativeStartupPolicy for IntegrationTestNativeStartup {
    fn initial_signing_key() -> Option<String> {
        std::env::var("ORBIS_SIGNING_KEY").ok()
    }
}
