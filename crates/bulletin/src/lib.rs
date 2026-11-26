pub mod error;
#[cfg(feature = "startup")]
pub mod startup;
pub mod r#trait;
#[cfg(feature = "vera")]
pub mod vera;
pub use r#trait::{BulletinKind, BulletinWriteKind};

// In-memory mock backend. Kept out of a plain production build unless the
// caller explicitly requests the type for an in-process harness.
#[cfg(any(test, feature = "dummy-type"))]
pub mod dummy;

// `BulletinFactoryImpl` is what the node's services composer builds against.
// Selection is gated on `select-vera`, not plainly on `vera`: `cli-tool`
// compiles the `vera` module for its own direct use of `VeraBulletin` without
// constructing a factory.
#[cfg(all(feature = "select-vera", not(feature = "fixture-startup")))]
pub type BulletinFactoryImpl = vera::startup::VeraBulletinFactory;
#[cfg(all(feature = "select-vera", feature = "fixture-startup"))]
pub type BulletinFactoryImpl =
    vera::startup::VeraBulletinFactory<vera::fixture_startup::FixtureVeraStartup>;

pub mod reporting;
