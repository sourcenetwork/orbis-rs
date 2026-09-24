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
//! - [`vera_container`] — [`VeraTestContainer`], a standalone Vera chain.
//! - [`network`] — [`IntegrationTestNetwork`]/[`IntegrationTestNetworkBuilder`],
//!   Vera plus orbis-node instances.

mod compose;
mod network;
mod vera_container;

pub use network::{IntegrationTestNetwork, IntegrationTestNetworkBuilder, NodeInfo};
pub use vera_container::VeraTestContainer;
