//! Deployment-trust bootstrap for a native (Commonware / vera.rs) reader.

use vera_client::{ClientError, VeraClient};
use vera_domain::ConsensusPublicKey;

#[derive(Debug, thiserror::Error)]
pub enum DeploymentTrustError {
    #[error("failed to read the deployment revision: {0}")]
    ReadDeployment(#[source] ClientError),
    #[error("consensus proof does not bind the configured deployment")]
    Mismatch,
}

/// Verify that `reader`'s finalized revision 1 binds the configured
/// deployment root, establishing trust before serving any request. Call
/// once, right after constructing the reader client.
pub async fn verify_deployment_root(
    reader: &VeraClient,
    trusted: &ConsensusPublicKey,
    root: [u8; 32],
) -> Result<(), DeploymentTrustError> {
    let first = reader
        .read_finalized_revision(1, trusted)
        .await
        .map_err(DeploymentTrustError::ReadDeployment)?;
    if first
        .parent_hash
        .strip_prefix("0x")
        .unwrap_or(&first.parent_hash)
        != hex::encode(root)
    {
        return Err(DeploymentTrustError::Mismatch);
    }
    Ok(())
}
