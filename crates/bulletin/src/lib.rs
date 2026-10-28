pub mod error;
#[cfg(feature = "native")]
pub mod native;
#[cfg(feature = "startup")]
pub mod startup;
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

// `BulletinFactoryImpl` is what the node's services composer builds against
// — one build selects exactly one implementation at compile time.
// `BulletinImpl` above remains for tests/tooling that construct a backend
// directly without going through the startup lifecycle.
//
// Selection is gated on `select-native`/`select-vera`, not plainly on
// `native`/`vera`: other crates in this workspace (`cli-tool`, for its
// always-on chain-admin functionality) legitimately need both modules
// compiled into the same binary for their own direct use of
// `BulletinImpl`/`NativeBulletin`, without that implying anything about
// which one orbis-node's own services composer should treat as canonical.
// Only the binary actually selecting a factory (orbis-node) turns on a
// `select-*` feature.
#[cfg(all(feature = "select-native", feature = "select-vera"))]
compile_error!(
    "Features 'select-native' and 'select-vera' are mutually exclusive for BulletinFactoryImpl."
);

#[cfg(feature = "select-native")]
pub use native::startup::NativeBulletinFactory as BulletinFactoryImpl;
#[cfg(feature = "select-vera")]
pub use vera::startup::VeraBulletinFactory as BulletinFactoryImpl;

pub mod reporting;
