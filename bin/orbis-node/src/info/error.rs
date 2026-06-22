use crate::error::{GrpcErrorClassification, GrpcServiceError};
use thiserror::Error;

/// DKG (Distributed Key Generation) related errors
#[derive(Error, Debug)]
pub enum InfoError {
    #[error("Error getting Info: {0}")]
    InfoError(String),

    #[error("{0}")]
    RingNotFound(String),
}

impl GrpcServiceError for InfoError {
    const SERVICE: &'static str = "info";

    fn classification(&self) -> GrpcErrorClassification {
        match self {
            InfoError::InfoError(_) => {
                GrpcErrorClassification::new(tonic::Code::Internal, tracing::Level::ERROR, false)
            }
            InfoError::RingNotFound(_) => {
                GrpcErrorClassification::new(tonic::Code::NotFound, tracing::Level::TRACE, false)
            }
        }
    }
}

/// Convert InfoError to tonic::Status for gRPC responses
impl From<InfoError> for tonic::Status {
    fn from(error: InfoError) -> Self {
        error.into_status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GrpcServiceError;
    use tonic::Code;
    use tracing::Level;

    #[test]
    fn classifies_every_info_error_variant() {
        let cases = vec![
            (
                InfoError::InfoError("test".into()),
                Code::Internal,
                Level::ERROR,
                false,
            ),
            (
                InfoError::RingNotFound("test".into()),
                Code::NotFound,
                Level::TRACE,
                false,
            ),
        ];

        for (error, code, level, record_failure) in cases {
            let classification = error.classification();
            assert_eq!(classification.code, code, "{error}");
            assert_eq!(classification.level, level, "{error}");
            assert_eq!(classification.record_failure, record_failure, "{error}");
        }
    }

    #[test]
    fn conversion_preserves_info_error_message() {
        let error = InfoError::RingNotFound("missing ring state".into());
        let expected = error.to_string();
        let status = tonic::Status::from(error);

        assert_eq!(status.code(), Code::NotFound);
        assert_eq!(status.message(), expected);
    }
}
