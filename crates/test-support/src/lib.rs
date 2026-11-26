//! Docker Compose orchestration for integration tests: a Vera chain plus
//! orbis-node containers, brought up/down around a test. Compiled only when
//! this crate is pulled in as a `[dev-dependencies]` entry; it is never part
//! of any production build.
//!
//! Prerequisites on `PATH`: `docker` (with the Compose plugin) and `curl` — the
//! health probes shell out to both, and a missing binary surfaces indirectly as
//! a "failed to become healthy" panic rather than a clear error.
//!
//! - [`compose`] — Docker Compose subprocess helpers.
//! - [`network`] — [`VeraNetworkAdapter`], the chain-plus-orbis-node-instances
//!   lifecycle type `VeraTestEnvironment` constructs.
//! - `container` / `vera_network` — Vera containers with explicit stop, crash
//!   and restart control, enabled with the `vera` feature.
//! - [`fixture`] — [`fixture::ScenarioFixture`]/[`fixture::TestEnvironment`]
//!   vocabulary. The `TestEnvironment` implementation lives in
//!   `bin/orbis-node/src/tests/e2e/vera_environment.rs`.
//! - [`node_readiness`] — `InfoService`-polling helper.

mod compose;
pub mod fixture;
mod network;
pub mod node_readiness;

pub use admin::BackendAdmin;
#[cfg(feature = "vera")]
pub use compose::{build_cli_tool_sidecar_image, run_sidecar_container};
pub use network::NodeInfo;
#[cfg(all(unix, feature = "vera"))]
pub use network::VeraNetworkAdapter;

pub mod admin;

#[cfg(unix)]
mod container;
#[cfg(unix)]
pub use container::{bind_mount_user, ContainerError, ContainerExit, ContainerNode, VeraImage};

#[cfg(all(unix, feature = "vera"))]
mod vera_network;
#[cfg(all(unix, feature = "vera"))]
pub use vera_network::{VeraTestNetwork, VeraTestNode};
// Free-function Compose primitives for callers outside this crate that hold
// a long-lived handle to one named service (e.g.
// `bin/orbis-node/src/tests/e2e/vera_lifecycle.rs`'s `Node`) — see
// `vera_network::compose_build`'s doc comment.
#[cfg(all(unix, feature = "vera"))]
pub use vera_network::{
    compose_build, compose_discover_endpoint, compose_exit_code, compose_kill, compose_save_logs,
    compose_start, compose_stop, compose_up,
};
