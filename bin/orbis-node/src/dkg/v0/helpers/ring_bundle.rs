//! Persisting `RingShareBundle` (share + polynomial) after a completed DKG,
//! PSS refresh, or reshare.

use super::committee::{in_committee, node_index_in};
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::messages::SessionKind;
use crate::dkg::v0::session_state::ReshareParams;
use crate::ring_state::RingShareBundle;
use crypto::r#trait::{CryptoDeserialize, DkgRole, PriShare};
use crypto::{CryptoSerialize, GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::LocalStorage;
use zeroize::Zeroizing;

/// Writes the `RingShareBundle` (share + polynomial) after a completed DKG, PSS refresh,
/// or reshare.
///
/// - `Fresh`   — write directly under `aggregate_pk`.
/// - `Refresh` — load old bundle, fold in the delta share and polynomial, write back
///   under the original ring key.
/// - `Reshare` — write a fresh bundle under the old ring key (the new share replaces
///   the old one; the ring public key is unchanged).
///
/// `combine_pub_poly` encapsulates curve-specific polynomial combination (Refresh only).
pub fn build_refresh_ring_bundle<S: LocalStorage>(
    storage: &S,
    ring_pk_hex: &str,
    final_share_bytes: &[u8],
    pub_poly_bytes: &[u8],
    now_secs: u64,
    session_id: u128,
    combine_pub_poly: impl Fn(&[u8], &[u8]) -> std::result::Result<Vec<u8>, String>,
) -> Result<RingShareBundle> {
    // PSS Refresh: load old bundle, add delta share + polynomial, return the
    // candidate bundle without writing it. The caller decides whether to stage
    // or persist it.
    let old_bundle = RingShareBundle::load_by_ring_key(storage, ring_pk_hex).map_err(|e| {
        DkgError::Storage(format!("Refresh: failed to load old share bundle: {}", e))
    })?;

    let old_pri = old_bundle.pri_share().map_err(|e| {
        DkgError::Deserialization(format!("Refresh: failed to deserialize old share: {}", e))
    })?;
    let delta_pri = PriShare::<Fr>::from_bytes(final_share_bytes).map_err(|e| {
        DkgError::Deserialization(format!("Refresh: failed to deserialize delta share: {}", e))
    })?;
    let new_pri = PriShare {
        i: old_pri.i,
        v: old_pri.v + delta_pri.v,
    };
    let new_share_bytes = CryptoSerialize::to_bytes(&new_pri).map_err(|e| {
        DkgError::Serialization(format!(
            "Refresh: failed to serialize combined share: {}",
            e
        ))
    })?;

    let old_poly_bytes = hex::decode(&old_bundle.public_polynomial).map_err(|e| {
        DkgError::Deserialization(format!(
            "Refresh: failed to decode old polynomial hex: {}",
            e
        ))
    })?;
    let new_poly_bytes = combine_pub_poly(&old_poly_bytes, pub_poly_bytes)
        .map_err(|e| DkgError::Crypto(format!("Refresh: failed to combine polynomials: {}", e)))?;

    tracing::debug!(
        session_id = session_id,
        ring_key = %ring_pk_hex,
        "Refresh: built staged RingShareBundle"
    );

    Ok(RingShareBundle {
        share_bytes: Zeroizing::new(new_share_bytes),
        public_polynomial: hex::encode(&new_poly_bytes),
        last_pss: now_secs,
    })
}

pub fn persist_ring_bundle<S: LocalStorage>(
    storage: &S,
    kind: &SessionKind,
    final_share_bytes: &[u8],
    pub_poly_bytes: &[u8],
    aggregate_pk: &G1Affine,
    now_secs: u64,
    session_id: u128,
    combine_pub_poly: impl Fn(&[u8], &[u8]) -> std::result::Result<Vec<u8>, String>,
) -> Result<()> {
    match kind {
        SessionKind::Fresh => {
            // Fresh DKG: single atomic write of share + polynomial.
            // Use now_secs so the PSS scheduler waits a full pss_interval before the
            // first refresh rather than treating the ring as immediately overdue.
            let bundle = RingShareBundle {
                share_bytes: Zeroizing::new(final_share_bytes.to_vec()),
                public_polynomial: hex::encode(pub_poly_bytes),
                last_pss: now_secs,
            };
            bundle
                .save(storage, aggregate_pk)
                .map_err(|e| DkgError::Storage(format!("Failed to store share bundle: {}", e)))?;
        }
        SessionKind::FreshPet { ring_id } => {
            // PET checking key: single atomic write of share + polynomial, keyed
            // by ring_id rather than the just-computed pet_pk — the pet_pk has
            // no stable identity to key by until this very write completes.
            // See the checking-key lifecycle design in
            // docs/plans/pet-integration.md.
            let bundle = RingShareBundle {
                share_bytes: Zeroizing::new(final_share_bytes.to_vec()),
                public_polynomial: hex::encode(pub_poly_bytes),
                last_pss: now_secs,
            };
            bundle.save_by_ring_key(storage, ring_id).map_err(|e| {
                DkgError::Storage(format!("Fresh PET: failed to store share bundle: {}", e))
            })?;
        }
        SessionKind::Refresh { ring_pk_hex } => {
            let new_bundle = build_refresh_ring_bundle(
                storage,
                ring_pk_hex,
                final_share_bytes,
                pub_poly_bytes,
                now_secs,
                session_id,
                combine_pub_poly,
            )?;
            new_bundle
                .save_by_ring_key(storage, ring_pk_hex)
                .map_err(|e| {
                    DkgError::Storage(format!("Refresh: failed to store new bundle: {}", e))
                })?;

            tracing::info!(
                session_id = session_id,
                ring_key = %ring_pk_hex,
                "Refresh: Phase 4 complete — RingShareBundle updated atomically"
            );
        }
        SessionKind::Reshare { ring_pk_hex, .. } => {
            // Reshare: the computed share is the full new share (not a delta).
            // Write it under the old ring key — the ring public key is unchanged.
            let bundle = RingShareBundle {
                share_bytes: Zeroizing::new(final_share_bytes.to_vec()),
                public_polynomial: hex::encode(pub_poly_bytes),
                last_pss: now_secs,
            };
            bundle.save_by_ring_key(storage, ring_pk_hex).map_err(|e| {
                DkgError::Storage(format!("Reshare: failed to store share bundle: {}", e))
            })?;

            tracing::info!(
                session_id = session_id,
                ring_key = %ring_pk_hex,
                "Reshare: Phase 4 complete — RingShareBundle written under old ring key"
            );
        }
    }
    Ok(())
}

/// Determine this node's role, `node_id`, and `ReshareParams` for a reshare session.
///
/// Returns `(node_id, role, params)`:
/// - `node_id` — 1-based index in the old committee for Dealer/DealerReceiver, new committee
///   for pure Receiver.
/// - `role` — `Dealer`, `Receiver`, or `DealerReceiver`.
/// - `params` — reshare session parameters including the pre-loaded old share (Dealers only).
///
/// Errors if this node is not in either committee, or if the old share cannot be loaded for
/// a node that is in the old committee.
pub fn build_reshare_params<S: LocalStorage>(
    ring_pk_hex: &str,
    old_peer_node_keys: &[String],
    new_peer_node_keys: &[String],
    new_threshold: u32,
    bulletin_post_id: &str,
    our_node_key: &str,
    local_storage: &S,
) -> Result<(u32, DkgRole, ReshareParams<Fr>)> {
    let mut sorted_old = old_peer_node_keys.to_vec();
    sorted_old.sort();
    let mut sorted_new = new_peer_node_keys.to_vec();
    sorted_new.sort();

    let in_old = in_committee(&sorted_old, our_node_key);
    let in_new = in_committee(&sorted_new, our_node_key);

    let role = match (in_old, in_new) {
        (true, true) => DkgRole::DealerReceiver,
        (true, false) => DkgRole::Dealer,
        (false, true) => DkgRole::Receiver,
        (false, false) => {
            return Err(DkgError::InvalidInput(
                "Reshare: this node is not in either committee".to_string(),
            ))
        }
    };

    let new_node_id: Option<u32> = if in_new {
        Some(node_index_in(&sorted_new, our_node_key)?)
    } else {
        None
    };
    let node_id: u32 = if in_old {
        node_index_in(&sorted_old, our_node_key)?
    } else {
        // Role match above guarantees in_new is true when in_old is false.
        new_node_id.expect("unreachable: in_new is true when in_old is false")
    };

    let old_share = if in_old {
        let bundle = RingShareBundle::load_by_ring_key(local_storage, ring_pk_hex)
            .map_err(|e| DkgError::Storage(format!("Reshare: failed to load old share: {}", e)))?;
        let pri = bundle.pri_share().map_err(|e| {
            DkgError::Deserialization(format!("Reshare: failed to deserialize old share: {}", e))
        })?;
        Some(pri.v)
    } else {
        None
    };

    let participating_ids: Vec<u32> = (1..=old_peer_node_keys.len() as u32).collect();

    let params = ReshareParams {
        old_share,
        participating_ids,
        new_threshold: new_threshold as usize,
        new_total_nodes: new_peer_node_keys.len(),
        new_peer_node_keys: sorted_new,
        new_node_id,
        bulletin_post_id: bulletin_post_id.to_string(),
    };

    Ok((node_id, role, params))
}
