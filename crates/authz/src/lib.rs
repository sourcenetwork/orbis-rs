pub mod error;
pub mod r#trait;

#[cfg(feature = "sourcehub")]
pub mod sourcehub;

// Only available in test builds via the test-helpers feature; never compiled into production binaries.
#[cfg(feature = "test-helpers")]
pub mod dummy;

#[cfg(feature = "sourcehub")]
pub use sourcehub::SourceHubAuth as AuthzImpl;
