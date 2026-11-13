pub mod error;
#[cfg(all(feature = "fixture-startup", feature = "select-vera"))]
mod fixture_startup;
#[cfg(feature = "native")]
pub mod native;
#[cfg(feature = "startup")]
pub mod startup;
pub mod r#trait;
pub use r#trait::{BulletinKind, BulletinWriteKind};

#[cfg(feature = "vera")]
pub mod vera;

// In-memory mock backend. Kept out of a plain production build unless the
// caller explicitly requests the type for an in-process harness.
#[cfg(any(test, feature = "dummy-type"))]
pub mod dummy;

// Export the selected implementation
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

#[cfg(all(feature = "select-native", not(feature = "fixture-startup")))]
pub type BulletinFactoryImpl = native::startup::NativeBulletinFactory;
#[cfg(all(feature = "select-native", feature = "fixture-startup"))]
pub type BulletinFactoryImpl =
    native::startup::NativeBulletinFactory<native::fixture_startup::FixtureNativeStartup>;
#[cfg(all(feature = "select-vera", not(feature = "fixture-startup")))]
pub type BulletinFactoryImpl = vera::startup::VeraBulletinFactory;
#[cfg(all(feature = "select-vera", feature = "fixture-startup"))]
pub type BulletinFactoryImpl =
    vera::startup::VeraBulletinFactory<fixture_startup::FixtureVeraStartup>;

pub mod reporting;
