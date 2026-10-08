//! Certified authorization with exact revision anchors and bounded freshness.

use crate::{error::Result as AuthzResult, r#trait::Authz, request::AccessCheckRequest};
use async_trait::async_trait;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use vera_client::{
    AccessRequest, Actor, ModuleId, Object, Operation, VeraClient, PERMISSION_LIMITS,
    RECORD_PROOF_BYTES,
};
use vera_domain::{ConsensusPublicKey, LightBlock};

pub mod error;
pub use error::Error;

pub struct NativeAuth {
    client: VeraClient,
    trusted: ConsensusPublicKey,
    root: String,
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
        let first = client
            .read_finalized_revision(1, &trusted)
            .await
            .map_err(Error::ReadDeployment)?;
        let root = hex::encode(root);
        if first
            .parent_hash
            .strip_prefix("0x")
            .unwrap_or(&first.parent_hash)
            != root
        {
            return Err(Error::DeploymentMismatch);
        }
        Ok(Self {
            client,
            trusted,
            root,
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

    fn anchor(&self, revision: &LightBlock) -> String {
        format!(
            "{}:{}:{}",
            self.root,
            revision.height,
            revision
                .block_hash
                .strip_prefix("0x")
                .unwrap_or(&revision.block_hash)
        )
    }

    async fn revision(&self, anchor: &str) -> Result<LightBlock, Error> {
        let (height, hash) = parse_anchor(&self.root, anchor)?;
        let revision = self
            .client
            .read_finalized_revision(height, &self.trusted)
            .await
            .map_err(Error::ReadRevision)?;
        if revision
            .block_hash
            .strip_prefix("0x")
            .unwrap_or(&revision.block_hash)
            != hash
        {
            return Err(Error::AnchorMismatch);
        }
        Ok(revision)
    }
}

fn check_freshness(timestamp: u64, now: u64, maximum_age: u64) -> Result<(), Error> {
    if timestamp > now.saturating_add(15) || now.saturating_sub(timestamp) > maximum_age {
        return Err(Error::StaleEvidence);
    }
    Ok(())
}

fn parse_anchor<'a>(root: &str, anchor: &'a str) -> Result<(u64, &'a str), Error> {
    if anchor.len() > 160 {
        return Err(Error::AnchorTooLarge);
    }
    let mut fields = anchor.split(':');
    let (Some(deployment), Some(height), Some(hash)) =
        (fields.next(), fields.next(), fields.next())
    else {
        return Err(Error::InvalidAnchor);
    };
    let number: u64 = height.parse().map_err(Error::AnchorHeight)?;
    if deployment != root
        || number == 0
        || number.to_string() != height
        || fields.next().is_some()
        || hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidAnchor);
    }
    Ok((number, hash))
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
    async fn check_at(
        &self,
        permission: Vec<u8>,
        subject: &str,
        anchor: &str,
    ) -> AuthzResult<bool> {
        let Some((policy, request)) = request(&permission, subject)? else {
            return Ok(false);
        };
        let revision = self.revision(anchor).await?;
        Ok(self
            .client
            .verify_access_at(
                &policy,
                &request,
                &revision,
                &self.trusted,
                PERMISSION_LIMITS,
            )
            .await
            .map_err(Error::VerifyAnchoredAccess)?)
    }
    async fn current_anchor(&self) -> AuthzResult<String> {
        let requested_minimum = self.minimum.load(Ordering::Acquire);
        let response = self
            .client
            .read_current_record(
                ModuleId::Vera,
                b"orbis/authz/anchor/v1",
                requested_minimum,
                &self.trusted,
                RECORD_PROOF_BYTES,
            )
            .await
            .map_err(Error::ReadCurrentAnchor)?;
        self.observe(
            requested_minimum,
            response.revision.height,
            response.revision.timestamp,
        )?;
        Ok(self.anchor(&response.revision))
    }
    async fn anchor_time(&self, anchor: &str) -> AuthzResult<u64> {
        Ok(self.revision(anchor).await?.timestamp)
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
            root: "11".repeat(32),
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
    fn native_authorization_rejects_ambiguous_windows_and_revision_anchors() {
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
        let root = "11".repeat(32);
        let hash = "22".repeat(32);
        assert_eq!(
            parse_anchor(&root, &format!("{root}:42:{hash}")).unwrap(),
            (42, hash.as_str())
        );
        for anchor in [
            format!("{root}:0:{hash}"),
            format!("{root}:042:{hash}"),
            format!("{root}:42:{hash}:x"),
            format!("{hash}:42:{hash}"),
        ] {
            assert!(parse_anchor(&root, &anchor).is_err());
        }
        assert!(check_freshness(70, 100, 30).is_ok());
        assert!(check_freshness(69, 100, 30).is_err());
        assert!(check_freshness(115, 100, 30).is_ok());
        assert!(check_freshness(116, 100, 30).is_err());
    }
}
