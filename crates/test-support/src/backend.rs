//! Which chain the integration-test harness provisions and drives.

/// Selects which chain backend [`crate::IntegrationTestNetwork`] provisions.
///
/// `Cosmos` preserves today's behavior and is the default on every existing
/// call site that doesn't explicitly pick a backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IntegrationBackend {
    #[default]
    Cosmos,
    NativeVera,
}
