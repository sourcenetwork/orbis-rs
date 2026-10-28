//! Backend-owned identity preparation, node registration, and the generic
//! node-services composer. `BulletinFactory`/`PreparedBulletin` select and
//! construct one `Bulletin` implementation, parallel to
//! `authz::startup::{AuthzFactory, PreparedAuthz}`; [`services`] combines
//! whichever two implementations a build selected with no backend-specific
//! branching of its own.

#[cfg(feature = "cosmos-identity")]
pub mod cosmos;
mod services;

pub use services::{
    ConnectedNodeServices, NodeServicesConfig, PreparedNodeServices, ServicesFactory,
};

use crate::{
    error::BulletinError,
    r#trait::{Bulletin, BulletinKind, BulletinWriteKind, NodeInfo},
};
use async_trait::async_trait;
use common::startup::{PrepareContext, StartupProgress};
use serde::de::DeserializeOwned;
use std::{path::PathBuf, sync::Arc};
use thiserror::Error;

/// Public identity exposed by the node before and after backend connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_key: String,
    pub public_address: String,
}

/// What the node asks the connected bulletin to register this process as.
/// Computed at the node level — it needs the local `Network` peer id, which
/// `bulletin` has no dependency on — then handed to `connect_and_register` as
/// plain data.
#[derive(Clone, Debug)]
pub struct NodeRegistration {
    pub controller_key: String,
    pub peer_id: String,
    pub whitelisted_policy_ids: Vec<String>,
    pub whitelisted_ring_ids: Vec<String>,
}

/// Selects and constructs one `Bulletin` implementation. `Config` is loaded
/// by `serde` as part of the node's single services-config file (see
/// [`NodeServicesConfig`]); `prepare` does whatever local (non-network)
/// validation and identity setup the implementation needs before the network
/// connection in `PreparedBulletin::connect`.
pub trait BulletinFactory {
    /// Diagnostics name (logging/tracing), e.g. `"bulletin/native"`.
    const NAME: &'static str;
    type Config: DeserializeOwned;
    type Prepared: PreparedBulletin;

    fn prepare(
        config: Self::Config,
        context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, BulletinStartupError>;
}

/// A prepared identity whose backend has not yet connected.
#[async_trait]
pub trait PreparedBulletin: Send {
    fn identity(&self) -> &NodeIdentity;
    fn name(&self) -> &'static str;

    async fn connect(
        self: Box<Self>,
        progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn Bulletin + Send + Sync>, BulletinStartupError>;

    /// Connect, then ensure this node's `NodeInfo` exists and matches
    /// `registration` before returning. A default implementation covers both
    /// backends (registration is just `Bulletin::read`/`post`); override only
    /// if an implementation's registration write genuinely differs.
    async fn connect_and_register(
        self: Box<Self>,
        registration: NodeRegistration,
        progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn Bulletin + Send + Sync>, BulletinStartupError> {
        let node_key = self.identity().node_key.clone();
        let bulletin = self.connect(progress).await?;
        ensure_node_info(bulletin.as_ref(), &node_key, &registration).await?;
        Ok(bulletin)
    }
}

#[derive(Debug, Error)]
pub enum BulletinStartupError {
    #[error("{operation}: {path:?}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(any(feature = "cosmos-identity", feature = "native"))]
    #[error("signing identity storage failed")]
    Storage(#[from] local_storage::error::LocalStorageError),
    #[cfg(any(feature = "cosmos-identity", feature = "native"))]
    #[error("signing identity entropy failed")]
    Entropy(#[from] getrandom::Error),
    #[cfg(feature = "cosmos-identity")]
    #[error("stored signing identity is not UTF-8")]
    Encoding(#[from] std::str::Utf8Error),
    #[cfg(feature = "cosmos-identity")]
    #[error("chain signing identity failed")]
    Signer(#[from] common::blockchain::BlockchainError),
    #[cfg(feature = "native")]
    #[error("native worker initialization failed")]
    NativeWorker(#[from] vera_client::ClientError),
    #[error("node signing identity is missing")]
    MissingIdentity,
    #[error("invalid bulletin configuration: {0}")]
    Configuration(String),
    #[error("bulletin connection failed")]
    Connection(#[from] BulletinError),
    #[error("bulletin connection timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("node registration failed: {0}")]
    Registration(String),
    #[error("authorization connection failed")]
    Authorization(#[from] authz::startup::AuthzStartupError),
}

/// Case-insensitive comparison of the hex node-id portion of a peer id
/// (before any `@address` suffix). Deliberately reimplemented here in
/// miniature rather than reusing `orbis-node`'s own peer-id validation, which
/// is used far beyond registration (DKG/PRE/Sign/reporting) and shouldn't
/// become something this crate depends on. A malformed existing on-chain
/// record simply compares unequal (rejected as a mismatch below) rather than
/// getting its own "invalid peer_id" diagnostic — a node-level nuance this
/// crate doesn't own.
fn peer_identity_matches(existing: &str, expected: &str) -> bool {
    fn node_part(peer_id: &str) -> &str {
        peer_id.split('@').next().unwrap_or(peer_id)
    }
    node_part(existing).eq_ignore_ascii_case(node_part(expected))
}

/// Ensure the node has a matching `NodeInfo` record before serving traffic.
/// `registration.peer_id` must already be canonicalized by the caller.
pub async fn ensure_node_info(
    bulletin: &(dyn Bulletin + Send + Sync),
    node_key: &str,
    registration: &NodeRegistration,
) -> Result<(), BulletinStartupError> {
    let existing = match bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
    {
        Ok(post) => Some(NodeInfo::try_from(post)?),
        Err(BulletinError::NotFound { .. }) => None,
        Err(err) => return Err(err.into()),
    };

    if let Some(existing) = existing {
        if !peer_identity_matches(&existing.peer_id, &registration.peer_id) {
            return Err(BulletinStartupError::Registration(format!(
                "existing node info for node_key {node_key} has peer_id {}, expected {}",
                existing.peer_id, registration.peer_id
            )));
        }
        if existing.controller_key != registration.controller_key {
            return Err(BulletinStartupError::Registration(format!(
                "existing node info for node_key {node_key} has controller_key {}, expected {}",
                existing.controller_key, registration.controller_key
            )));
        }
        if !registration.whitelisted_policy_ids.is_empty()
            || !registration.whitelisted_ring_ids.is_empty()
        {
            tracing::warn!(
                node_key = %node_key,
                policy_id_count = registration.whitelisted_policy_ids.len(),
                ring_id_count = registration.whitelisted_ring_ids.len(),
                "Existing node info found; ignoring startup whitelist flags because controller-owned updates must use UpdateNodeInfo"
            );
        }
        tracing::info!(
            node_key = %node_key,
            peer_id = %registration.peer_id,
            "Existing node info matches local identity"
        );
        return Ok(());
    }

    let node_info = NodeInfo {
        peer_id: registration.peer_id.clone(),
        controller_key: registration.controller_key.clone(),
        whitelisted_policy_ids: registration.whitelisted_policy_ids.clone(),
        whitelisted_ring_ids: registration.whitelisted_ring_ids.clone(),
    };
    let payload: Vec<u8> = node_info.try_into()?;
    let created_node_key = bulletin.post(BulletinWriteKind::NodeInfo, payload).await?;
    if created_node_key != node_key {
        return Err(BulletinStartupError::Registration(format!(
            "bulletin created node info under key {created_node_key}, expected {node_key}"
        )));
    }
    tracing::info!(
        node_key = %node_key,
        peer_id = %registration.peer_id,
        "Created node info"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dummy::DummyBulletin;

    fn registration(
        controller_key: &str,
        peer_id: &str,
        policy_ids: Vec<&str>,
        ring_ids: Vec<&str>,
    ) -> NodeRegistration {
        NodeRegistration {
            controller_key: controller_key.to_string(),
            peer_id: peer_id.to_string(),
            whitelisted_policy_ids: policy_ids.into_iter().map(str::to_string).collect(),
            whitelisted_ring_ids: ring_ids.into_iter().map(str::to_string).collect(),
        }
    }

    #[tokio::test]
    async fn ensure_node_info_keeps_existing_whitelists() {
        let bulletin = DummyBulletin::new().await.expect("create bulletin");
        let node_key = "node-key-existing";
        let existing = NodeInfo {
            peer_id: "peer-existing".to_string(),
            controller_key: "controller-key".to_string(),
            whitelisted_policy_ids: vec!["existing-policy".to_string()],
            whitelisted_ring_ids: vec!["ring-existing".to_string()],
        };
        bulletin
            .set_node_info(node_key.to_string(), existing.clone())
            .expect("seed node info");
        let registration = registration(
            "controller-key",
            "peer-existing",
            vec!["new-policy"],
            vec!["new-ring"],
        );

        ensure_node_info(&bulletin, node_key, &registration)
            .await
            .expect("ensure node info");

        let post = bulletin
            .read(node_key.to_string(), BulletinKind::NodeInfo)
            .await
            .expect("read existing node info");
        let node_info = NodeInfo::try_from(post).expect("parse node info");
        assert_eq!(
            node_info.whitelisted_policy_ids,
            existing.whitelisted_policy_ids
        );
        assert_eq!(
            node_info.whitelisted_ring_ids,
            existing.whitelisted_ring_ids
        );
    }

    #[tokio::test]
    async fn ensure_node_info_fails_when_existing_peer_mismatches() {
        let bulletin = DummyBulletin::new().await.expect("create bulletin");
        let node_key = "node-key-peer-mismatch";
        let existing = NodeInfo {
            peer_id: "different-peer".to_string(),
            controller_key: "controller-key".to_string(),
            whitelisted_policy_ids: vec![],
            whitelisted_ring_ids: vec![],
        };
        bulletin
            .set_node_info(node_key.to_string(), existing)
            .expect("seed node info");
        let registration = registration("controller-key", "expected-peer", vec![], vec![]);

        let err = ensure_node_info(&bulletin, node_key, &registration)
            .await
            .expect_err("peer mismatch should fail");
        assert!(err.to_string().contains("peer_id"));
    }

    #[tokio::test]
    async fn ensure_node_info_fails_when_existing_controller_mismatches() {
        let bulletin = DummyBulletin::new().await.expect("create bulletin");
        let node_key = "node-key-controller-mismatch";
        let existing = NodeInfo {
            peer_id: "peer-existing".to_string(),
            controller_key: "different-controller".to_string(),
            whitelisted_policy_ids: vec![],
            whitelisted_ring_ids: vec![],
        };
        bulletin
            .set_node_info(node_key.to_string(), existing)
            .expect("seed node info");
        let registration = registration("controller-key", "peer-existing", vec![], vec![]);

        let err = ensure_node_info(&bulletin, node_key, &registration)
            .await
            .expect_err("controller mismatch should fail");
        assert!(err.to_string().contains("controller_key"));
    }

    // The "no existing record" / create path isn't exercised against
    // `DummyBulletin`: it has no signer to derive a NodeInfo id, so
    // `DummyBulletin::post(NodeInfo)` always rejects (test setup goes
    // through `set_node_info` instead, which bypasses `post` entirely) —
    // same constraint the pre-refactor orbis-node tests worked around.
}
