//! Certified authorization with exact revision anchors and bounded freshness.

use crate::{
    error::{AuthZError, Result},
    r#trait::Authz,
    request::AccessCheckRequest,
};
use async_trait::async_trait;
use hub_client::{
    AccessRequest, Actor, HubClient, ModuleId, Object, Operation, PERMISSION_LIMITS,
    RECORD_PROOF_BYTES,
};
use hub_domain::{ConsensusPublicKey, LightBlock};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct NativeAuth {
    client: HubClient,
    trusted: ConsensusPublicKey,
    root: String,
    minimum: AtomicU64,
    maximum_age: u64,
}

fn invalid(error: impl std::fmt::Display) -> AuthZError {
    AuthZError::Native(error.to_string())
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(invalid)
}

impl NativeAuth {
    /// Bind consensus trust to the configured genesis before serving requests.
    pub async fn connect(
        client: HubClient,
        trusted: ConsensusPublicKey,
        root: [u8; 32],
        maximum_age: u64,
    ) -> Result<Self> {
        if root == [0; 32] || maximum_age == 0 {
            return Err(invalid("invalid deployment root or freshness bound"));
        }
        let first = client
            .read_finalized_revision(1, &trusted)
            .await
            .map_err(invalid)?;
        let root = hex::encode(root);
        if first
            .parent_hash
            .strip_prefix("0x")
            .unwrap_or(&first.parent_hash)
            != root
        {
            return Err(invalid(
                "consensus proof does not bind the configured deployment",
            ));
        }
        Ok(Self {
            client,
            trusted,
            root,
            minimum: AtomicU64::new(1),
            maximum_age,
        })
    }

    fn observe(&self, revision: &LightBlock) -> Result<()> {
        check_freshness(revision.timestamp, now()?, self.maximum_age)?;
        let previous = self.minimum.fetch_max(revision.height, Ordering::AcqRel);
        if revision.height < previous {
            return Err(invalid("authorization revision regressed"));
        }
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

    async fn revision(&self, anchor: &str) -> Result<LightBlock> {
        let (height, hash) = parse_anchor(&self.root, anchor)?;
        let revision = self
            .client
            .read_finalized_revision(height, &self.trusted)
            .await
            .map_err(invalid)?;
        if revision
            .block_hash
            .strip_prefix("0x")
            .unwrap_or(&revision.block_hash)
            != hash
        {
            return Err(invalid("anchor does not match certified revision"));
        }
        Ok(revision)
    }
}

fn check_freshness(timestamp: u64, now: u64, maximum_age: u64) -> Result<()> {
    if timestamp > now.saturating_add(15) || now.saturating_sub(timestamp) > maximum_age {
        return Err(invalid(
            "authorization evidence is stale or from the future",
        ));
    }
    Ok(())
}

fn parse_anchor<'a>(root: &str, anchor: &'a str) -> Result<(u64, &'a str)> {
    if anchor.len() > 160 {
        return Err(invalid("oversized revision anchor"));
    }
    let mut fields = anchor.split(':');
    let (Some(deployment), Some(height), Some(hash)) =
        (fields.next(), fields.next(), fields.next())
    else {
        return Err(invalid("invalid revision anchor"));
    };
    let number: u64 = height.parse().map_err(invalid)?;
    if deployment != root
        || number == 0
        || number.to_string() != height
        || fields.next().is_some()
        || hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid revision anchor"));
    }
    Ok((number, hash))
}

fn request(bytes: &[u8], subject: &str) -> Result<Option<(String, AccessRequest)>> {
    if bytes.len() > 64 << 10 || subject.len() > 512 {
        return Err(invalid("authorization request exceeds byte limit"));
    }
    let request = AccessCheckRequest::from_bytes(bytes)?;
    match (&request.valid_window, request.timestamp) {
        (Some(window), Some(timestamp)) => {
            if window.start > window.end {
                return Err(invalid("invalid authorization window"));
            }
            if timestamp < window.start || timestamp > window.end {
                return Ok(None);
            }
        }
        (None, None) => {}
        _ => {
            return Err(invalid(
                "timestamp and validity window must be provided together",
            ))
        }
    }
    let actor = Actor(subject.parse().map_err(invalid)?);
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
    async fn check(&self, permission: Vec<u8>, subject: &str) -> Result<bool> {
        let Some((policy, request)) = request(&permission, subject)? else {
            return Ok(false);
        };
        let (revision, allowed) = self
            .client
            .verify_current_access(
                &policy,
                &request,
                self.minimum.load(Ordering::Acquire),
                &self.trusted,
                PERMISSION_LIMITS,
            )
            .await
            .map_err(invalid)?;
        self.observe(&revision)?;
        Ok(allowed)
    }
    async fn check_at(&self, permission: Vec<u8>, subject: &str, anchor: &str) -> Result<bool> {
        let Some((policy, request)) = request(&permission, subject)? else {
            return Ok(false);
        };
        let revision = self.revision(anchor).await?;
        self.client
            .verify_access_at(
                &policy,
                &request,
                &revision,
                &self.trusted,
                PERMISSION_LIMITS,
            )
            .await
            .map_err(invalid)
    }
    async fn current_anchor(&self) -> Result<String> {
        let response = self
            .client
            .read_current_record(
                ModuleId::Hub,
                b"orbis/authz/anchor/v1",
                self.minimum.load(Ordering::Acquire),
                &self.trusted,
                RECORD_PROOF_BYTES,
            )
            .await
            .map_err(invalid)?;
        self.observe(&response.revision)?;
        Ok(self.anchor(&response.revision))
    }
    async fn anchor_time(&self, anchor: &str) -> Result<u64> {
        Ok(self.revision(anchor).await?.timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::ValidWindow;

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
