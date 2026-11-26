//! Signing-derivation requests, local delegation and the derived Sign public key.

use anyhow::{bail, Context, Result};
use crypto::{r#trait::ThresholdSigner, CryptoDeserialize, CryptoSerialize, GroupAffine, SignImpl};
use vera_client::{
    rings::RingState,
    threshold_objects::{KeyDerivation, ThresholdObject},
    DelegationScope,
};

/// Parse an SDK `KeyDerivation` and return it with its validated identity.
pub(crate) fn request(bytes: &[u8]) -> Result<(KeyDerivation, String)> {
    let derivation: KeyDerivation = serde_json::from_slice(bytes)?;
    let id = ThresholdObject::KeyDerivation(derivation.clone()).validated_id()?;
    Ok((derivation, id))
}

/// The delegation scopes whose requests this tool prepares.
pub(crate) fn scope(value: &str) -> Result<DelegationScope> {
    match value {
        "orbis:ring" => Ok(DelegationScope::ManageRings),
        "orbis:object:store" => Ok(DelegationScope::StoreThresholdObject),
        other => bail!("unsupported scope {other}; use orbis:ring or orbis:object:store"),
    }
}

/// The public key Sign sessions under this derivation verify against, once the ring is active.
pub(crate) fn derived_public_key(
    ring: &RingState,
    derivation: &KeyDerivation,
) -> Result<Option<String>> {
    let RingState::Active { keys } = ring else {
        return Ok(None);
    };
    let ring_key = GroupAffine::from_bytes(&hex::decode(&keys.public_key)?)
        .context("ring public key is not a point on this build's curve")?;
    let metadata = SignImpl::encode_metadata(
        &derivation.policy_id,
        &derivation.resource,
        &derivation.permission,
    );
    let derived =
        SignImpl::derive_public_key(&ring_key, derivation.derivation.as_bytes(), Some(&metadata))?;
    Ok(Some(hex::encode(derived.to_bytes()?)))
}
