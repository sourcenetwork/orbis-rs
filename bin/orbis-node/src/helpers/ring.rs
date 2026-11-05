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
    /// Mirrors `RingPayload::pre_share_endpoints` — non-empty selects the
    /// Defra-backed storage delivery mode over today's direct response.
    pub pre_share_endpoints: Vec<String>,
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

/// Resolves the ring's public polynomial for this node, the local share bundle (when
/// `self_in_list`), and the hex-encoded polynomial actually used — the same single
/// snapshot on every branch. Callers that need to pin this request to a specific
/// generation (see `PreRequestContext::pinned_public_polynomial`) must pin from the
/// returned hex string, not from `ring.public_polynomial_hex` independently — when
/// `self_in_list`, this function ignores that field in favor of a fresher read, so a
/// pin taken from `ring.public_polynomial_hex` could disagree with it.
pub fn load_ring_pub_poly_and_bundle<D>(
    storage: &impl LocalStorage,
    ring: &RingConfig,
    self_in_list: bool,
) -> Result<(D::PubPoly, Option<RingShareBundle>, String), String>
where
    D: Dkg<PublicKey = G1Affine>,
{
    if !self_in_list {
        let hex = ring.public_polynomial_hex.clone();
        return Ok((decode_pub_poly_hex::<D>(&hex)?, None, hex));
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
        let hex = ring.public_polynomial_hex.clone();
        return Ok((decode_pub_poly_hex::<D>(&hex)?, None, hex));
    };

    let polynomial = decode_pub_poly_hex::<D>(&bundle.public_polynomial)
        .map_err(|error| format!("bundle polynomial: {error}"))?;
    let hex = bundle.public_polynomial.clone();
    Ok((polynomial, Some(bundle), hex))
}

fn decode_pub_poly_hex<D: Dkg>(hex_str: &str) -> Result<D::PubPoly, String> {
    let bytes = hex::decode(hex_str)
        .map_err(|error| format!("Failed to decode polynomial hex: {error}"))?;
    <D::PubPoly>::from_bytes(&bytes)
        .map_err(|error| format!("Failed to deserialize public polynomial: {error}"))
}
