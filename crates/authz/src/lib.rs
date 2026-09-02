pub mod error;
pub mod r#trait;

#[cfg(feature = "vera")]
pub mod vera;

// Available only when the `test-helpers` feature is enabled (typically in tests).
#[cfg(feature = "test-helpers")]
pub mod dummy;

#[cfg(feature = "vera")]
pub use vera::VeraAuth as AuthzImpl;
