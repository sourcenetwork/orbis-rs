//! Certified authorization with exact revision anchors and bounded freshness.

use crate::{
    error::Result as AuthzResult, r#trait::Authz, r#trait::VerifiedEvidence,
    request::AccessCheckRequest,
};
use async_trait::async_trait;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use vera_client::{
    AccessRequest, Actor, ClientError, Object, Operation, PermissionResponse, VeraClient,
    PERMISSION_LIMITS,
};
use vera_domain::ConsensusPublicKey;

pub mod error;
#[cfg(feature = "startup")]
pub mod startup;
pub use error::Error;

pub struct NativeAuth {
    client: VeraClient,
    trusted: ConsensusPublicKey,
    minimum: AtomicU64,
    maximum_age: u64,
}

fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(Error::Clock)
}

impl NativeAuth {
    /// Bind consensus trust to the configured genesis before serving requests.
    pub async fn connect(
        client: VeraClient,
        trusted: ConsensusPublicKey,
        root: [u8; 32],
        maximum_age: u64,
    ) -> Result<Self, Error> {
        if root == [0; 32] || maximum_age == 0 {
            return Err(Error::InvalidConfiguration);
        }
        common::blockchain::native::verify_deployment_root(&client, &trusted, root)
            .await
            .map_err(Error::DeploymentTrust)?;
        Ok(Self {
            client,
            trusted,
            minimum: AtomicU64::new(1),
            maximum_age,
        })
    }

    fn observe(&self, requested_minimum: u64, height: u64, timestamp: u64) -> Result<(), Error> {
        check_freshness(timestamp, now()?, self.maximum_age)?;
        if height < requested_minimum {
            return Err(Error::RevisionRegressed);
        }
        self.minimum.fetch_max(height, Ordering::AcqRel);
        Ok(())
    }
}

fn check_freshness(timestamp: u64, now: u64, maximum_age: u64) -> Result<(), Error> {
    if timestamp > now.saturating_add(15) || now.saturating_sub(timestamp) > maximum_age {
        return Err(Error::StaleEvidence);
    }
    Ok(())
}

fn request(bytes: &[u8], subject: &str) -> Result<Option<(String, AccessRequest)>, Error> {
    if bytes.len() > 64 << 10 || subject.len() > 512 {
        return Err(Error::RequestTooLarge);
    }
    let request: AccessCheckRequest =
        serde_json::from_slice(bytes).map_err(Error::RequestDecode)?;
    match (&request.valid_window, request.timestamp) {
        (Some(window), Some(timestamp)) => {
            if window.start > window.end {
                return Err(Error::InvalidWindow);
            }
            if timestamp < window.start || timestamp > window.end {
                return Ok(None);
            }
        }
        (None, None) => {}
        _ => return Err(Error::IncompleteWindow),
    }
    let actor = Actor(subject.parse().map_err(Error::Subject)?);
    Ok(Some((
        request.policy_id,
        AccessRequest {
            actor,
            operations: vec![Operation {
                object: Object {
                    resource: request.resource,
                    id: request.object_id,
                },
                permission: request.permission,
            }],
        },
    )))
}

#[async_trait]
impl Authz for NativeAuth {
    async fn check(&self, permission: Vec<u8>, subject: &str) -> AuthzResult<bool> {
        let Some((policy, request)) = request(&permission, subject)? else {
            return Ok(false);
        };
        let requested_minimum = self.minimum.load(Ordering::Acquire);
        let (revision, allowed) = self
            .client
            .verify_current_access(
                &policy,
                &request,
                requested_minimum,
                &self.trusted,
                PERMISSION_LIMITS,
            )
            .await
            .map_err(Error::VerifyCurrentAccess)?;
        self.observe(requested_minimum, revision.height, revision.timestamp)?;
        Ok(allowed)
    }

    async fn capture_evidence(&self, permission: Vec<u8>, subject: &str) -> AuthzResult<Vec<u8>> {
        let Some((policy, request)) = request(&permission, subject)? else {
            return Err(Error::RequestOutsideWindow.into());
        };
        let requested_minimum = self.minimum.load(Ordering::Acquire);
        let response = self
            .client
            .current_permission_response(&policy, &request, requested_minimum, PERMISSION_LIMITS)
            .await
            .map_err(Error::CaptureEvidence)?;
        // Verify locally right away, same as `check` does via `verify_current_access` --
        // a bad RPC response fails fast here rather than being deferred to validate time.
        response
            .verify(
                &policy,
                &request,
                requested_minimum,
                &self.trusted,
                PERMISSION_LIMITS,
            )
            .map_err(ClientError::from)
            .map_err(Error::VerifyEvidence)?;
        self.observe(
            requested_minimum,
            response.revision.height,
            response.revision.timestamp,
        )?;
        Ok(serde_json::to_vec(&response).map_err(Error::EvidenceEncode)?)
    }

    async fn verify_evidence(
        &self,
        evidence: &[u8],
        permission: Vec<u8>,
        subject: &str,
    ) -> AuthzResult<VerifiedEvidence> {
        if evidence.len() > 64 << 10 {
            return Err(Error::EvidenceTooLarge.into());
        }
        let Some((policy, request)) = request(&permission, subject)? else {
            return Ok(VerifiedEvidence {
                captured_at: 0,
                allowed: false,
            });
        };
        let response: PermissionResponse =
            serde_json::from_slice(evidence).map_err(Error::EvidenceDecode)?;
        let allowed = response
            .verify(&policy, &request, 0, &self.trusted, PERMISSION_LIMITS)
            .map_err(ClientError::from)
            .map_err(Error::VerifyEvidence)?;
        Ok(VerifiedEvidence {
            captured_at: response.revision.timestamp,
            allowed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::ValidWindow;

    #[test]
    fn native_request_validation_preserves_decode_and_identity_sources() {
        use std::error::Error as _;

        let error = request(b"{", "did:key:reader").unwrap_err();
        assert!(matches!(error, Error::RequestDecode(_)));
        assert!(error.source().unwrap().is::<serde_json::Error>());

        let permission = AccessCheckRequest::new(
            "11".repeat(32),
            "document".into(),
            "doc".into(),
            "read".into(),
            None,
            None,
            None,
        );
        let error = request(&permission.to_bytes().unwrap(), "not-a-did").unwrap_err();
        assert!(matches!(error, Error::Subject(_)));
        assert!(error.source().unwrap().is::<vera_identity::Error>());
        assert!(matches!(
            request(&vec![b' '; (64 << 10) + 1], "did:key:reader"),
            Err(Error::RequestTooLarge)
        ));
        assert!(matches!(
            request(&permission.to_bytes().unwrap(), &"x".repeat(513)),
            Err(Error::RequestTooLarge)
        ));
    }

    #[test]
    fn overlapping_authorization_reads_preserve_the_minimum() {
        let keys = vera_harness::cluster::KeySet::builder()
            .seed(9071)
            .build()
            .unwrap();
        let auth = NativeAuth {
            client: VeraClient::new("http://127.0.0.1:1"),
            trusted: *keys.epoch_info().output.public().public(),
            minimum: AtomicU64::new(5),
            maximum_age: 30,
        };
        let requested = auth.minimum.load(Ordering::Acquire);
        let timestamp = now().unwrap();
        auth.observe(requested, 12, timestamp).unwrap();
        auth.observe(requested, 10, timestamp).unwrap();
        assert_eq!(auth.minimum.load(Ordering::Acquire), 12);
        assert!(auth.observe(12, 10, timestamp).is_err());
        assert!(auth.observe(12, 20, timestamp - 31).is_err());
        assert!(auth.observe(12, 20, timestamp + 60).is_err());
        assert_eq!(auth.minimum.load(Ordering::Acquire), 12);
    }

    #[test]
    fn native_authorization_rejects_ambiguous_windows() {
        let mut permission = AccessCheckRequest::new(
            "11".repeat(32),
            "document".into(),
            "doc".into(),
            "read".into(),
            None,
            None,
            None,
        );
        assert!(request(&permission.to_bytes().unwrap(), "did:key:reader")
            .unwrap()
            .is_some());
        permission.timestamp = Some(10);
        assert!(request(&permission.to_bytes().unwrap(), "did:key:reader").is_err());
        permission.valid_window = Some(ValidWindow { start: 11, end: 20 });
        assert!(request(&permission.to_bytes().unwrap(), "did:key:reader")
            .unwrap()
            .is_none());
        permission.valid_window = Some(ValidWindow { start: 10, end: 10 });
        assert!(request(&permission.to_bytes().unwrap(), "did:key:reader")
            .unwrap()
            .is_some());
        assert!(check_freshness(70, 100, 30).is_ok());
        assert!(check_freshness(69, 100, 30).is_err());
        assert!(check_freshness(115, 100, 30).is_ok());
        assert!(check_freshness(116, 100, 30).is_err());
    }
}
