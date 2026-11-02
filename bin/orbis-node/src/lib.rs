// `app_state`/`constants`/`dkg`/`helpers`/`info`/`pre`/`sign`/`store_secret`
// are `pub` (not just `pub(crate)`) so the shared, in-process node bootstrap
// at `src/tests/support/live_node.rs` can reach their service/type
// constructors as `orbis_node::...` from the separate `native_startup` test
// binary crate, the same way `ring_state` was promoted for PR 5d's
// `pending_ring_cancellation.rs` — test-only reach, no production behavior
// change.
pub mod app_state;
pub mod constants;
pub mod dkg;
mod error;
#[cfg(feature = "harness")]
pub mod harness;
pub mod helpers;
pub mod info;
mod metrics;
mod pet;
pub mod pre;
mod pss;
pub mod reporting;
pub mod ring_state;
mod runtime;
pub mod sign;
pub mod store_secret;
#[cfg(feature = "unsafe-testing")]
mod unsafe_testing;

pub use helpers::launch::{Args, NetworkIngressArgs};
pub use runtime::run;
#[cfg(test)]
pub(crate) use runtime::{
    complete_initialization_or_shutdown, shutdown_bootstrap_after_init, start_bootstrap_info_server,
};

#[cfg(any(test, feature = "integration-test"))]
pub use runtime::{init_node, InitializedNode, NodeConfig};

#[cfg(test)]
mod tests;
