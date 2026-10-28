//! Shared node-startup types used by the `authz` and `bulletin` trait crates.
//!
//! Both crates need these in their own trait signatures (`AuthzFactory`/
//! `BulletinFactory`, `PreparedAuthz`/`PreparedBulletin`), and `bulletin`
//! depends on `authz` for its services composer — defining these here,
//! rather than in either crate, is what keeps that a one-way dependency.

use std::path::Path;

/// Coarse connection-progress phases a backend can report while starting up.
/// Not every implementation reports every phase (e.g. a backend with no
/// funding step never emits `WaitingForFunding`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionPhase {
    Connecting,
    WaitingForFunding,
    Funded,
}

/// Callback for a backend to report connection progress during `connect`/
/// `connect_and_register`. Implemented for any matching closure, so callers
/// can keep passing a plain `|phase| ...` where a `&dyn StartupProgress` is
/// expected.
pub trait StartupProgress: Send + Sync {
    fn set_phase(&self, phase: ConnectionPhase);
}

impl<F: Fn(ConnectionPhase) + Send + Sync> StartupProgress for F {
    fn set_phase(&self, phase: ConnectionPhase) {
        self(phase)
    }
}

/// Storage and filesystem handles shared by every backend's `prepare` step.
#[derive(Clone, Copy)]
pub struct PrepareContext<'a> {
    pub storage: &'a local_storage::LocalStorageImpl,
    pub runtime_base_path: &'a Path,
}
