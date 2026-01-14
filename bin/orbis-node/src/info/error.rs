use thiserror::Error;

/// DKG (Distributed Key Generation) related errors
#[derive(Error, Debug)]
pub enum InfoError {
    #[error("Error getting Info: {0}")]
    InfoError(String),
}

/// Result type for DKG operations
pub type Result<T> = std::result::Result<T, InfoError>;

/// Convert DkgError to tonic::Status for gRPC responses
impl From<InfoError> for tonic::Status {
    fn from(error: InfoError) -> Self {
        use tonic::Code;
        match error {
            _ => tonic::Status::new(Code::Internal, error.to_string()),
        }
    }
}
