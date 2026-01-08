use thiserror::Error;

/// Bulletin related errors
#[derive(Error, Debug)]
pub enum BulletinError {}

/// Result type for local storage operations
pub type Result<T> = std::result::Result<T, BulletinError>;
