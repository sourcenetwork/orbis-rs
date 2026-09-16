pub mod error;
pub mod r#trait;
pub use r#trait::{BulletinKind, BulletinWriteKind};

#[cfg(feature = "vera")]
pub mod vera;

// In-memory mock backend. Kept out of a plain production build (no `test`
// cfg, no opt-in feature) — see `dummy-type` below for why this is separate
// from the `dummy` feature that selects it as `BulletinImpl`.
#[cfg(any(test, feature = "dummy-type"))]
pub mod dummy;

// Enforce mutual exclusivity - only one backend can be selected
#[cfg(all(feature = "vera", feature = "dummy"))]
compile_error!("Features 'vera' and 'dummy' are mutually exclusive. Use --no-default-features to disable the default backend.");

// Export the selected implementation
#[cfg(feature = "dummy")]
pub use dummy::DummyBulletin as BulletinImpl;
#[cfg(feature = "vera")]
pub use vera::VeraBulletin as BulletinImpl;
