use std::future::Future;
use std::time::Duration;

use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::DkgRole;
use crypto::SignImpl;
use crypto::THRESHOLD_SIGNATURE_SCHEME;

use crate::constants::{RESHARE_SIGNATURE_MAX_ATTEMPTS, RESHARE_SIGNATURE_RETRY_DELAY};
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::{effective_new_peer_node_keys, peer_node_keys_match};
use crate::dkg::v0::messages::SessionKind;
use crate::dkg::v0::session_state::ReshareSignatureReadyKey;
use crate::dkg::v0::transport::AttemptKey;
use crate::helpers::ring::RingConfig;
use crate::ring_state::RingShareBundle;
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse, SigningOptions};
use crate::sign::v0::error::SignError;
use crate::sign::v0::helpers::{
    finalized_ring_payload_reshare_sign_state_sha256_hex,
    ring_payload_reshare_sign_state_sha256_hex, ring_reshare_update_message,
};
use crate::sign::v0::messages::{
    RingReshareUpdateContext, RingReshareUpdateStatement, SignContext, RING_RESHARE_UPDATE_DOMAIN,
};

use super::super::types::{CoordinatorDkg, CoordinatorReportSigner};
use super::super::{attempt_state_error, DkgCoordinator};

#[derive(Clone)]
struct PreparedReshareUpdate {
    ready_key: ReshareSignatureReadyKey,
    sorted_new_peer_node_keys: Vec<String>,
    new_route_peer_ids: Vec<String>,
    new_committee_size: usize,
    ring_id: String,
    current_ring_sha256: String,
    finalized_ring_sha256: String,
    block_number_nonce: u64,
    chain_id: String,
}

/// What a non-Dealer Reshare node needs to promote or discard its own staged
/// bundle once `wait_for_reshare_bulletin_finalized` observes the bulletin's
/// pending-reshare fields clear. Produced for every such node (not just node
/// 1), since promotion/discard is a per-node decision made independently.
#[derive(Clone)]
pub(crate) struct ReshareReadinessInfo {
    pub(crate) ready_key: ReshareSignatureReadyKey,
    pub(crate) expected_new_committee: Vec<String>,
    pub(crate) expected_new_threshold: u32,
}

#[allow(clippy::too_many_arguments)]
pub async fn update_bulletin_if_selector<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    kind: &SessionKind,
    dkg_role: DkgRole,
    storage_key: &str,
    ring_pk_bytes: &[u8],
    pub_poly_bytes: &[u8],
    reshare_new_peer_node_keys: Option<&[String]>,
    reshare_bulletin_post_id: Option<&str>,
    reshare_staged_bundle: Option<RingShareBundle>,
) -> Result<Option<ReshareReadinessInfo>>
where
    D: CoordinatorDkg + Send + Sync,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    let SessionKind::Reshare {
        ring_pk_hex,
        new_peer_node_keys,
        new_threshold,
        ..
    } = kind
    else {
        return Ok(None);
    };

    let prepared_update = if dkg_role == DkgRole::Dealer {
        None
    } else {
        let staged_bundle = reshare_staged_bundle.ok_or_else(|| {
            DkgError::InvalidState(
                "Reshare: non-Dealer node reached bulletin update without a staged bundle"
                    .to_string(),
            )
        })?;
        Some(
            prepare_reshare_update(
                coord,
                attempt,
                storage_key,
                new_peer_node_keys,
                *new_threshold,
                reshare_new_peer_node_keys,
                reshare_bulletin_post_id,
                staged_bundle,
            )
            .await?,
        )
    };

    let readiness_info = prepared_update
        .as_ref()
        .map(|prepared| ReshareReadinessInfo {
            ready_key: prepared.ready_key.clone(),
            expected_new_committee: prepared.sorted_new_peer_node_keys.clone(),
            expected_new_threshold: *new_threshold,
        });

    let reshare_new_node_id = reshare_new_node_id(
        coord,
        reshare_new_peer_node_keys.unwrap_or(new_peer_node_keys),
    );

    if reshare_new_node_id != 1 {
        return Ok(readiness_info);
    }

    let Some(prepared) = prepared_update else {
        return Err(DkgError::ProtocolError(
            "Reshare: node 1 selected to update bulletin without ready update state".to_string(),
        ));
    };

    let statement = RingReshareUpdateStatement {
        domain: RING_RESHARE_UPDATE_DOMAIN.to_string(),
        session_id,
        chain_id: prepared.chain_id,
        ring_pk: hex::encode(ring_pk_bytes),
        ring_id: prepared.ring_id.clone(),
        current_ring_sha256: prepared.current_ring_sha256,
        finalized_ring_sha256: prepared.finalized_ring_sha256,
        block_number_nonce: prepared.block_number_nonce,
    };
    let message_to_sign = ring_reshare_update_message(&*coord.app_state.bulletin, &statement)
        .map_err(|e| {
            DkgError::Serialization(format!(
                "Reshare: failed to serialize ring update statement: {}",
                e
            ))
        })?;
    let sign_coordinator =
        SignCoordinator::<D, SignImpl>::with_routes(coord.app_state.clone(), coord.routes);
    let ring_config = RingConfig {
        ring_id: prepared.ring_id.clone(),
        ring_pk_bytes: ring_pk_bytes.to_vec(),
        peer_ids: prepared.new_route_peer_ids,
        peer_node_keys: prepared.sorted_new_peer_node_keys,
        threshold: *new_threshold as usize,
        total_participants: prepared.new_committee_size,
        public_polynomial_hex: hex::encode(pub_poly_bytes),
    };
    let sign_context =
        SignContext::RingReshareUpdate(Box::new(RingReshareUpdateContext { statement }));

    let response_bytes = collect_reshare_update_signature_with_retry(
        session_id,
        RESHARE_SIGNATURE_RETRY_DELAY,
        |request_id| {
            sign_coordinator.initiate_signing(
                request_id,
                ring_config.clone(),
                message_to_sign.clone(),
                sign_context.clone(),
                SigningOptions::default(),
            )
        },
    )
    .await
    .map_err(|e| {
        DkgError::Crypto(format!(
            "Reshare: failed to collect threshold signature for RingPayload update: {}",
            e
        ))
    })?;
    let sign_response: SignResponse = serde_json::from_slice(&response_bytes).map_err(|e| {
        DkgError::Deserialization(format!(
            "Reshare: failed to parse threshold signature response: {}",
            e
        ))
    })?;

    if sign_response.signature.is_empty() {
        return Err(DkgError::Crypto(
            "Reshare: threshold signature response was empty".to_string(),
        ));
    }

    let signature_bytes = hex::decode(&sign_response.signature).map_err(|e| {
        DkgError::Crypto(format!(
            "Reshare: failed to decode threshold signature hex: {}",
            e
        ))
    })?;
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |_| ())
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    coord
        .app_state
        .bulletin
        .update(
            prepared.ring_id.clone(),
            THRESHOLD_SIGNATURE_SCHEME.to_string(),
            signature_bytes,
        )
        .await
        .map_err(|e| DkgError::Bulletin(format!("Reshare: failed to update RingPayload: {}", e)))?;

    tracing::info!(
        ring_pk = %ring_pk_hex,
        ring_id = %prepared.ring_id,
        new_threshold = new_threshold,
        new_committee_size = prepared.new_committee_size,
        signature_len = sign_response.signature.len(),
        "Reshare: Successfully updated RingPayload on bulletin"
    );

    Ok(readiness_info)
}

#[allow(clippy::too_many_arguments)]
async fn prepare_reshare_update<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    storage_key: &str,
    new_peer_node_keys: &[String],
    new_threshold: u32,
    reshare_new_peer_node_keys: Option<&[String]>,
    reshare_bulletin_post_id: Option<&str>,
    staged_bundle: RingShareBundle,
) -> Result<PreparedReshareUpdate>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    let sorted_new_peer_node_keys = reshare_new_peer_node_keys
        .map(|peers| peers.to_vec())
        .unwrap_or_else(|| new_peer_node_keys.to_vec());
    let new_committee_size = sorted_new_peer_node_keys.len();
    let new_route_peer_ids =
        new_committee_peer_ids_from_session(coord, attempt, new_committee_size).await?;
    let ring_id = reshare_bulletin_post_id.ok_or_else(|| {
        DkgError::Bulletin("Reshare: missing ring id for updated RingPayload".to_string())
    })?;

    let current_post = coord
        .app_state
        .bulletin
        .read(ring_id.to_string(), BulletinKind::Ring)
        .await
        .map_err(|e| {
            DkgError::Bulletin(format!(
                "Reshare: failed to read current RingPayload before signing: {}",
                e
            ))
        })?;

    let current_ring_payload: RingPayload =
        serde_json::from_slice(&current_post.payload).map_err(|e| {
            DkgError::Deserialization(format!(
                "Reshare: failed to parse current RingPayload before signing: {}",
                e
            ))
        })?;
    let payload_new_peer_node_keys = effective_new_peer_node_keys(&current_ring_payload);
    let payload_new_threshold = current_ring_payload
        .new_threshold
        .unwrap_or(current_ring_payload.threshold);
    if !peer_node_keys_match(payload_new_peer_node_keys, &sorted_new_peer_node_keys) {
        return Err(DkgError::ProtocolError(format!(
            "Reshare: current RingPayload new_peer_node_keys {:?} do not match session new_peer_node_keys {:?}",
            payload_new_peer_node_keys, sorted_new_peer_node_keys
        )));
    }
    if payload_new_threshold != new_threshold {
        return Err(DkgError::ProtocolError(format!(
            "Reshare: current RingPayload new_threshold {} does not match session new_threshold {}",
            payload_new_threshold, new_threshold
        )));
    }
    let current_ring_sha256 = ring_payload_reshare_sign_state_sha256_hex(&current_ring_payload);
    let finalized_ring_sha256 =
        finalized_ring_payload_reshare_sign_state_sha256_hex(&current_ring_payload);
    let chain_id = coord.app_state.bulletin.chain_id();

    let ready_key = ReshareSignatureReadyKey {
        ring_key: storage_key.to_string(),
        session_id,
        attempt_id: attempt.attempt_id,
        ring_id: ring_id.to_string(),
        current_ring_sha256: current_ring_sha256.clone(),
        finalized_ring_sha256: finalized_ring_sha256.clone(),
    };
    if !coord
        .app_state
        .dkg_session_state
        .mark_reshare_signature_ready_for_attempt(attempt, ready_key.clone(), staged_bundle)
        .await
    {
        return Err(DkgError::StaleAttempt {
            ceremony_id: session_id,
        });
    }

    Ok(PreparedReshareUpdate {
        ready_key,
        sorted_new_peer_node_keys,
        new_route_peer_ids,
        new_committee_size,
        ring_id: ring_id.to_string(),
        current_ring_sha256,
        finalized_ring_sha256,
        block_number_nonce: current_ring_payload.block_number_nonce,
        chain_id,
    })
}

async fn new_committee_peer_ids_from_session<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    new_committee_size: usize,
) -> Result<Vec<String>>
where
    D: CoordinatorDkg,
{
    let peer_ids = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            (1..=new_committee_size as u32)
                .filter_map(|node_id| {
                    state
                        .routing
                        .reshare_new_node_id_to_peer_id
                        .get(&node_id)
                        .cloned()
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

    if peer_ids.len() != new_committee_size {
        return Err(DkgError::ProtocolError(format!(
            "Reshare: new committee routing map has {} entries, expected {}",
            peer_ids.len(),
            new_committee_size
        )));
    }

    Ok(peer_ids)
}

fn reshare_new_node_id<D>(coord: &DkgCoordinator<D>, reshare_new_peer_node_keys: &[String]) -> u32
where
    D: CoordinatorDkg,
{
    reshare_new_peer_node_keys
        .iter()
        .position(|node_key| node_key == &coord.app_state.node_key)
        .map(|i| (i + 1) as u32)
        .unwrap_or(0)
}

fn is_retryable_reshare_signature_error(error: &SignError) -> bool {
    matches!(
        error,
        SignError::ReshareInProgress | SignError::InsufficientShares { .. } | SignError::Timeout(_)
    )
}

async fn collect_reshare_update_signature_with_retry<F, Fut>(
    session_id: u128,
    retry_delay: Duration,
    mut sign_attempt: F,
) -> std::result::Result<Vec<u8>, SignError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = std::result::Result<Vec<u8>, SignError>>,
{
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let request_id = format!("reshare-update-{}-{}", session_id, attempt);
        let result = sign_attempt(request_id).await;
        if let Err(error) = &result {
            if attempt < RESHARE_SIGNATURE_MAX_ATTEMPTS
                && is_retryable_reshare_signature_error(error)
            {
                tracing::warn!(
                    session_id = session_id,
                    attempt = attempt,
                    error = %error,
                    "Reshare: threshold signature not ready yet, retrying"
                );
                tokio::time::sleep(retry_delay).await;
                continue;
            }
        }
        return result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[tokio::test]
    async fn reshare_signature_retry_uses_unique_request_ids() {
        let calls = RefCell::new(Vec::new());
        let response = collect_reshare_update_signature_with_retry(
            42,
            Duration::from_millis(0),
            |request_id| {
                let attempt = {
                    let mut calls = calls.borrow_mut();
                    calls.push(request_id);
                    calls.len()
                };
                async move {
                    if attempt < 3 {
                        Err(SignError::ReshareInProgress)
                    } else {
                        Ok(vec![7, 8, 9])
                    }
                }
            },
        )
        .await
        .expect("third retry should succeed");

        assert_eq!(response, vec![7, 8, 9]);
        assert_eq!(
            calls.into_inner(),
            vec![
                "reshare-update-42-1".to_string(),
                "reshare-update-42-2".to_string(),
                "reshare-update-42-3".to_string(),
            ]
        );
    }
}
