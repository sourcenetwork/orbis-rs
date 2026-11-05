use thiserror::Error;

#[derive(Debug, Error)]
pub enum PreShareError {
    #[error("unsupported stored-share envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("stored-share envelope signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error("failed to sign stored-share envelope: {0}")]
    Signing(String),
}

pub type Result<T> = std::result::Result<T, PreShareError>;
