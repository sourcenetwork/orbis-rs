pub mod error;
pub mod r#trait;

#[cfg(feature = "sourcehub")]
pub mod sourcehub;

// Available only when the `test-helpers` feature is enabled (typically in tests).
#[cfg(feature = "test-helpers")]
pub mod dummy;

#[cfg(feature = "sourcehub")]
pub use sourcehub::SourceHubAuth as AuthzImpl;
