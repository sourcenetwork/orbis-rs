pub mod error;
pub mod r#trait;

#[cfg(feature = "sourcehub")]
pub mod sourcehub;

#[cfg(feature = "hubrs")]
pub mod hubrs;

// Export dummy for testing anyways
pub mod dummy;

// Enforce mutual exclusivity - only one backend can be selected
#[cfg(all(feature = "sourcehub", feature = "dummy"))]
compile_error!("Features 'sourcehub' and 'dummy' are mutually exclusive. Use --no-default-features to disable the default backend.");

#[cfg(all(feature = "sourcehub", feature = "hubrs"))]
compile_error!("Features 'sourcehub' and 'hubrs' are mutually exclusive. Use --no-default-features to disable the default backend.");

#[cfg(all(feature = "dummy", feature = "hubrs"))]
compile_error!("Features 'dummy' and 'hubrs' are mutually exclusive. Use --no-default-features to disable the default backend.");

// Export the selected implementation
#[cfg(feature = "dummy")]
pub use dummy::DummyBulletin as BulletinImpl;
#[cfg(feature = "hubrs")]
pub use hubrs::HubRsBulletin as BulletinImpl;
#[cfg(feature = "sourcehub")]
pub use sourcehub::SourceHubBulletin as BulletinImpl;
