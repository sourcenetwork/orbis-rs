//! DKG: starting a distributed key generation session.

use std::time::Duration;

use authn::{create_authenticated_request, JwtSigner};
use proto::v0::dkg::dkg_service_client::DkgServiceClient;
use proto::v0::dkg::StartDkgRequest;
use tonic::{Code, Status};

use crate::client::OrbisClient;
use crate::error::{Result, SdkError};

const DKG_START_MAX_ATTEMPTS: usize = 3;
const DKG_START_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Result of a DKG operation.
#[derive(Debug, Clone)]
pub struct DkgResult {
    pub session_id: String,
    pub status: String,
    pub message: String,
}

impl OrbisClient {
    /// Starts a DKG session for a pre-created, blank ring entry. DKG has no
    /// durable-identity concept today — authorized by a fresh, throwaway
    /// self-signed JWT minted for this one call, not a caller-supplied
    /// identity, since starting the ceremony for a ring isn't gated on
    /// *who* asks.
    pub async fn start_dkg(&self, ring_id: impl Into<String>) -> Result<DkgResult> {
        let ring_id = ring_id.into();
        let mut client = DkgServiceClient::new(self.channel());

        let jwt_signer = JwtSigner::new();
        let token = jwt_signer
            .create_dkg_jwt(&ring_id)
            .map_err(|e| SdkError::Crypto(format!("failed to create DKG JWT: {e}")))?;

        let mut response = None;
        for attempt in 1..=DKG_START_MAX_ATTEMPTS {
            let request = StartDkgRequest {
                ring_id: ring_id.clone(),
            };
            let tonic_request = create_authenticated_request(request, &token)
                .map_err(|e| SdkError::Crypto(format!("failed to attach JWT: {e}")))?;

            match client.start_dkg(tonic_request).await {
                Ok(ok) => {
                    response = Some(ok);
                    break;
                }
                Err(status)
                    if attempt < DKG_START_MAX_ATTEMPTS
                        && is_retryable_dkg_start_error(&status) =>
                {
                    tokio::time::sleep(DKG_START_RETRY_DELAY).await;
                }
                Err(status) => return Err(status.into()),
            }
        }

        let response = response
            .expect("the DKG retry loop above always returns or stores a response")
            .into_inner();
        Ok(DkgResult {
            session_id: response.session_id,
            status: response.status,
            message: response.message,
        })
    }
}

fn is_retryable_dkg_start_error(status: &Status) -> bool {
    status.code() == Code::Unavailable
        && status.message().to_ascii_lowercase().contains("timed out")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_retryable_dkg_start_error_only_matches_unavailable_timeout() {
        assert!(is_retryable_dkg_start_error(&Status::unavailable(
            "peer dial timed out"
        )));
        assert!(!is_retryable_dkg_start_error(&Status::unavailable(
            "connection refused"
        )));
        assert!(!is_retryable_dkg_start_error(&Status::internal(
            "timed out"
        )));
    }
}
