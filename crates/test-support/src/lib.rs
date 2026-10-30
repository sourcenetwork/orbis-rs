//! Docker Compose orchestration for integration tests: a Vera chain plus
//! orbis-node containers, brought up/down around a test. Compiled only when
//! this crate is pulled in as a `[dev-dependencies]` entry; it is never part
//! of any production build.
//!
//! Prerequisites on `PATH`: `docker` (with the Compose plugin) and `curl` — the
//! health probes shell out to both, and a missing binary surfaces indirectly as
//! a "failed to become healthy" panic rather than a clear error.
//!
//! - [`compose`] — Docker Compose subprocess helpers shared by the two below.
//! - [`vera_container`] — [`VeraTestContainer`], a standalone Vera chain (Cosmos only).
//! - [`network`] — [`IntegrationTestNetwork`]/[`IntegrationTestNetworkBuilder`],
//!   dispatching over [`IntegrationBackend`] to either the Cosmos or native Vera
//!   chain plus orbis-node instances. Backend-specific administration remains
//!   outside this lifecycle wrapper until shared scenarios require it.
//! - `container` / `native_network` — native containers with explicit stop, crash
//!   and restart control, enabled with the `native` feature.
//! - [`fixture`] — backend-neutral [`fixture::ScenarioFixture`]/
//!   [`fixture::TestEnvironment`] vocabulary; additive, not yet wired to
//!   [`IntegrationBackend`] or any concrete backend.
//! - [`environment`] (`cosmos` feature) — [`CosmosTestEnvironment`], the
//!   compile-time-selected `fixture::TestEnvironment` for Cosmos. Native's
//!   counterpart lives outside this crate; see that module's doc comment.
//! - [`node_readiness`] — shared `InfoService`-polling helper both
//!   `TestEnvironment` implementations use.

mod backend;
mod compose;
#[cfg(feature = "cosmos")]
mod environment;
pub mod fixture;
mod network;
pub mod node_readiness;

pub use admin::BackendAdmin;
pub use backend::IntegrationBackend;
#[cfg(feature = "cosmos")]
pub use environment::CosmosTestEnvironment;
#[cfg(feature = "cosmos")]
pub use network::CosmosNetwork;
#[cfg(all(unix, feature = "native"))]
pub use network::NativeNetworkAdapter;
pub use network::{IntegrationTestNetwork, IntegrationTestNetworkBuilder, NodeInfo};

#[cfg(feature = "cosmos")]
mod vera_container;
#[cfg(feature = "cosmos")]
pub use vera_container::VeraTestContainer;

pub mod admin;

#[cfg(unix)]
mod container;
#[cfg(unix)]
pub use container::{bind_mount_user, ContainerError, ContainerExit, ContainerNode, NativeImage};

#[cfg(all(unix, feature = "native"))]
mod native_network;
#[cfg(all(unix, feature = "native"))]
pub use native_network::{NativeTestNetwork, NativeTestNode};
// Free-function Compose primitives for callers outside this crate that hold
// a long-lived handle to one named service (e.g.
// `bin/orbis-node/tests/native_startup.rs`'s `Node`) — see
// `native_network::compose_build`'s doc comment.
#[cfg(all(unix, feature = "native"))]
pub use native_network::{
    compose_build, compose_discover_endpoint, compose_exit_code, compose_kill, compose_save_logs,
    compose_start, compose_stop, compose_up,
};
