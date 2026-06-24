use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportingError {
    #[error("invalid report: {0}")]
    InvalidReport(String),
    #[error("report authorization failed: {0}")]
    Unauthorized(String),
    #[error("report target is reachable")]
    TargetReachable,
    #[error("report has expired")]
    Expired,
    #[error("unsupported report type {name}")]
    UnsupportedReportType { name: String },
    #[error("bulletin error: {0}")]
    Bulletin(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("reporting capacity reached")]
    CapacityReached,
}

pub type Result<T> = std::result::Result<T, ReportingError>;
