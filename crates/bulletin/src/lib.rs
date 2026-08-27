pub mod error;
pub mod r#trait;
pub use r#trait::{BulletinKind, BulletinWriteKind};

#[cfg(feature = "vera")]
pub mod vera;

// Export dummy for testing anyways
pub mod dummy;

// Enforce mutual exclusivity - only one backend can be selected
#[cfg(all(feature = "vera", feature = "dummy"))]
compile_error!("Features 'vera' and 'dummy' are mutually exclusive. Use --no-default-features to disable the default backend.");

// Export the selected implementation
#[cfg(feature = "dummy")]
pub use dummy::DummyBulletin as BulletinImpl;
#[cfg(feature = "vera")]
pub use vera::VeraBulletin as BulletinImpl;
