use thiserror::Error;

#[derive(Debug, Error)]
pub enum PreShareError {
    #[error("unsupported stored-share envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("stored-share envelope signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error("failed to sign stored-share envelope: {0}")]
    Signing(String),
    #[error("failed to mint Defra bearer JWT: {0}")]
    Jwt(String),
    #[error("unsupported PRE-share retrieval manifest version {0}")]
    UnsupportedManifestVersion(u8),
    #[error("malformed PRE-share retrieval data: {0}")]
    Malformed(String),
    #[error("insufficient verified PRE-share entries: got {got}, need {need}")]
    InsufficientVerifiedEntries { got: usize, need: usize },
    #[error("PRE-share entries disagree on capability derivation")]
    InconsistentDerivation,
    #[error("failed to recover re-encrypted commitment: {0}")]
    RecoveryFailed(String),
}

pub type Result<T> = std::result::Result<T, PreShareError>;
