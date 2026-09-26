pub mod error;
#[cfg(feature = "native")]
pub mod native;
pub mod request;
pub mod r#trait;

#[cfg(feature = "vera")]
pub mod vera;

// Available only when the `test-helpers` feature is enabled (typically in tests).
#[cfg(feature = "test-helpers")]
pub mod dummy;

#[cfg(feature = "vera")]
pub use vera::VeraAuth as AuthzImpl;
