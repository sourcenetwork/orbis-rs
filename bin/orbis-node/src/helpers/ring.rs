use crate::dkg::v0::session_state::SessionStateManager;
use crate::ring_state::RingShareBundle;
use crypto::r#trait::{CryptoDeserialize, Dkg};
use crypto::GroupAffine as G1Affine;
use local_storage::r#trait::LocalStorage;

#[derive(Debug, Clone)]
pub struct RingConfig {
    pub ring_id: String,
    pub ring_pk_bytes: Vec<u8>,
    pub peer_ids: Vec<String>,
    pub peer_node_keys: Vec<String>,
    pub threshold: usize,
    pub total_participants: usize,
    pub public_polynomial_hex: String,
}

pub async fn is_ring_reshare_in_progress<D: Dkg + 'static>(
    ring_pk_bytes: &[u8],
    session_state: &SessionStateManager<D>,
) -> bool {
    let Ok(ring_pk) = G1Affine::from_bytes(ring_pk_bytes) else {
        return false;
    };
    session_state.is_ring_pss_active(&ring_pk.to_string()).await
}

pub fn load_ring_pub_poly_and_bundle<D>(
    storage: &impl LocalStorage,
    ring: &RingConfig,
    self_in_list: bool,
) -> Result<(D::PubPoly, Option<RingShareBundle>), String>
where
    D: Dkg<PublicKey = G1Affine>,
{
    if !self_in_list {
        return Ok((decode_pub_poly_hex::<D>(&ring.public_polynomial_hex)?, None));
    }

    let ring_pk = G1Affine::from_bytes(&ring.ring_pk_bytes)
        .map_err(|error| format!("Failed to deserialize ring public key: {error}"))?;
    let Some(bundle) = RingShareBundle::load(storage, &ring_pk)
        .inspect_err(|error| {
            tracing::warn!(
                error = %error,
                "local bundle missing, falling back to ring config polynomial"
            );
        })
        .ok()
    else {
        return Ok((decode_pub_poly_hex::<D>(&ring.public_polynomial_hex)?, None));
    };

    let polynomial = decode_pub_poly_hex::<D>(&bundle.public_polynomial)
        .map_err(|error| format!("bundle polynomial: {error}"))?;
    Ok((polynomial, Some(bundle)))
}

fn decode_pub_poly_hex<D: Dkg>(hex_str: &str) -> Result<D::PubPoly, String> {
    let bytes = hex::decode(hex_str)
        .map_err(|error| format!("Failed to decode polynomial hex: {error}"))?;
    <D::PubPoly>::from_bytes(&bytes)
        .map_err(|error| format!("Failed to deserialize public polynomial: {error}"))
}
