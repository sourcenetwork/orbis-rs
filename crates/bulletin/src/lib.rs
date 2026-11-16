pub mod error;
#[cfg(all(feature = "fixture-startup", feature = "select-vera-go"))]
mod fixture_startup;
#[cfg(feature = "vera")]
pub mod vera;
#[cfg(feature = "startup")]
pub mod startup;
pub mod r#trait;
pub use r#trait::{BulletinKind, BulletinWriteKind};

#[cfg(feature = "vera-go")]
pub mod vera_go;

// In-memory mock backend. Kept out of a plain production build unless the
// caller explicitly requests the type for an in-process harness.
#[cfg(any(test, feature = "dummy-type"))]
pub mod dummy;

// Export the selected implementation
#[cfg(feature = "vera-go")]
pub use vera_go::VeraGoBulletin as BulletinImpl;

// `BulletinFactoryImpl` is what the node's services composer builds against
// — one build selects exactly one implementation at compile time.
// `BulletinImpl` above remains for tests/tooling that construct a backend
// directly without going through the startup lifecycle.
//
// Selection is gated on `select-vera`/`select-vera-go`, not plainly on
// `vera`/`vera-go`: other crates in this workspace (`cli-tool`, for its
// always-on chain-admin functionality) legitimately need both modules
// compiled into the same binary for their own direct use of
// `VeraBulletin`/`VeraGoBulletin`, without that implying anything about
// which one orbis-node's own services composer should treat as canonical.
// Only the binary actually selecting a factory (orbis-node) turns on a
// `select-*` feature.
#[cfg(all(feature = "select-vera", feature = "select-vera-go"))]
compile_error!(
    "Features 'select-vera' and 'select-vera-go' are mutually exclusive for BulletinFactoryImpl."
);

#[cfg(all(feature = "select-vera", not(feature = "fixture-startup")))]
pub type BulletinFactoryImpl = vera::startup::VeraBulletinFactory;
#[cfg(all(feature = "select-vera", feature = "fixture-startup"))]
pub type BulletinFactoryImpl =
    vera::startup::VeraBulletinFactory<vera::fixture_startup::FixtureVeraStartup>;
#[cfg(all(feature = "select-vera-go", not(feature = "fixture-startup")))]
pub type BulletinFactoryImpl = vera_go::startup::VeraGoBulletinFactory;
#[cfg(all(feature = "select-vera-go", feature = "fixture-startup"))]
pub type BulletinFactoryImpl =
    vera_go::startup::VeraGoBulletinFactory<fixture_startup::FixtureVeraGoStartup>;

pub mod reporting;
