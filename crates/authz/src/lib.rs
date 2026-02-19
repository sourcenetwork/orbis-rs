pub mod error;
pub mod r#trait;

#[cfg(feature = "sourcehub")]
pub mod sourcehub;

// Export dummy for testing anyways
pub mod dummy;

// Enforce mutual exclusivity - only one backend can be selected
#[cfg(all(feature = "sourcehub", feature = "dummy"))]
compile_error!("Features 'sourcehub' and 'dummy' are mutually exclusive. Use --no-default-features to disable the default backend.");

// Export the selected implementation
#[cfg(feature = "dummy")]
pub use dummy::DummyAuthZ as AuthzImpl;
#[cfg(feature = "sourcehub")]
pub use sourcehub::SourceHubAuth as AuthzImpl;

