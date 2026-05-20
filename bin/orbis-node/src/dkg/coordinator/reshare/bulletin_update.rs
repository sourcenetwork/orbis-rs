use std::future::Future;
use std::time::Duration;

use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::{DistKeyShare, DkgRole, PubShare, ThresholdSigner};
use crypto::THRESHOLD_SIGNATURE_SCHEME;
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignImpl, SignaturePoint};

use crate::constants::{RESHARE_SIGNATURE_MAX_ATTEMPTS, RESHARE_SIGNATURE_RETRY_DELAY};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::messages::SessionKind;
use crate::dkg::session_state::ReshareSignatureReadyKey;
use crate::helpers::helpers::{extract_node_part, RingConfig};
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::sign::error::SignError;
use crate::sign::helpers::ring_reshare_update_message;
use crate::sign::messages::{
    RingReshareUpdateContext, RingReshareUpdateStatement, SignContext, RING_RESHARE_UPDATE_DOMAIN,
};

use super::super::types::CoordinatorDkg;
use super::super::DkgCoordinator;

#[derive(Clone)]
struct PreparedReshareUpdate {
    sorted_new_peer_ids: Vec<String>,
    new_committee_size: usize,
    ring_id: String,
    sign_namespace: String,
    current_ring_sha256: String,
    finalized_ring_sha256: String,
    block_number_nonce: u64,
    chain_id: String,
}

pub(in crate::dkg::coordinator) async fn update_bulletin_if_selector<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    kind: &SessionKind,
    dkg_role: DkgRole,
    storage_key: &str,
    ring_pk_bytes: &[u8],
    pub_poly_bytes: &[u8],
    reshare_new_peer_ids: Option<&[String]>,
    reshare_bulletin_post_id: Option<&str>,
) -> Result<()>
where
    D: CoordinatorDkg + Send + Sync,
    SignImpl: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    let SessionKind::Reshare {
        ring_pk_hex,
        new_peer_ids,
        new_threshold,
        ..
    } = kind
    else {
        return Ok(());
    };

    let prepared_update = if dkg_role == DkgRole::Dealer {
        None
    } else {
        Some(
            prepare_reshare_update(
                coord,
                session_id,
                storage_key,
                new_peer_ids,
                *new_threshold,
                reshare_new_peer_ids,
                reshare_bulletin_post_id,
            )
            .await?,
        )
    };

    let reshare_new_node_id =
        reshare_new_node_id(coord, reshare_new_peer_ids.unwrap_or(new_peer_ids));

    if reshare_new_node_id != 1 {
        return Ok(());
    }

    let Some(prepared) = prepared_update else {
        return Err(DkgError::ProtocolError(
            "Reshare: node 1 selected to update bulletin without ready update state".to_string(),
        ));
    };

    let bulletin_namespace = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| state.namespace.clone())
        .await
        .ok_or_else(|| {
            DkgError::SessionNotFound(format!(
                "Reshare: session {} not found when reading namespace for bulletin update",
                session_id
            ))
        })?;

    let statement = RingReshareUpdateStatement {
        domain: RING_RESHARE_UPDATE_DOMAIN.to_string(),
        session_id,
        chain_id: prepared.chain_id,
        namespace: prepared.sign_namespace.clone(),
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
    let sign_coordinator = SignCoordinator::<D, SignImpl>::new(coord.app_state.clone());
    let ring_config = RingConfig {
        ring_pk_bytes: ring_pk_bytes.to_vec(),
        peer_ids: prepared.sorted_new_peer_ids,
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
        .bulletin
        .update(
            bulletin_namespace.clone(),
            prepared.ring_id.clone(),
            THRESHOLD_SIGNATURE_SCHEME.to_string(),
            signature_bytes,
        )
        .await
        .map_err(|e| DkgError::Bulletin(format!("Reshare: failed to update RingPayload: {}", e)))?;

    tracing::info!(
        ring_pk = %ring_pk_hex,
        ring_id = %prepared.ring_id,
        namespace = %prepared.sign_namespace,
        new_threshold = new_threshold,
        new_committee_size = prepared.new_committee_size,
        signature_len = sign_response.signature.len(),
        "Reshare: Successfully updated RingPayload on bulletin"
    );

    Ok(())
}

async fn prepare_reshare_update<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    storage_key: &str,
    new_peer_ids: &[String],
    new_threshold: u32,
    reshare_new_peer_ids: Option<&[String]>,
    reshare_bulletin_post_id: Option<&str>,
) -> Result<PreparedReshareUpdate>
where
    D: CoordinatorDkg,
{
    let sorted_new_peer_ids = reshare_new_peer_ids
        .map(|peers| peers.to_vec())
        .unwrap_or_else(|| new_peer_ids.to_vec());
    let new_committee_size = sorted_new_peer_ids.len();
    let ring_id = reshare_bulletin_post_id.ok_or_else(|| {
        DkgError::Bulletin("Reshare: missing ring id for updated RingPayload".to_string())
    })?;
    let bulletin_namespace = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| state.namespace.clone())
        .await
        .ok_or_else(|| {
            DkgError::SessionNotFound(format!(
                "Reshare: session {} not found when reading namespace for bulletin read",
                session_id
            ))
        })?;

    let current_post = coord
        .app_state
        .bulletin
        .read(bulletin_namespace, ring_id.to_string(), BulletinKind::Ring)
        .await
        .map_err(|e| {
            DkgError::Bulletin(format!(
                "Reshare: failed to read current RingPayload before signing: {}",
                e
            ))
        })?;
    let sign_namespace = current_post.namespace.clone();
    let current_ring_payload: RingPayload =
        serde_json::from_slice(&current_post.payload).map_err(|e| {
            DkgError::Deserialization(format!(
                "Reshare: failed to parse current RingPayload before signing: {}",
                e
            ))
        })?;
    let payload_new_peer_ids = current_ring_payload
        .new_peer_ids
        .as_deref()
        .unwrap_or(&current_ring_payload.peer_ids)
        .to_vec();
    let payload_new_threshold = current_ring_payload
        .new_threshold
        .unwrap_or(current_ring_payload.threshold);
    if payload_new_peer_ids != sorted_new_peer_ids {
        return Err(DkgError::ProtocolError(format!(
            "Reshare: current RingPayload new_peer_ids {:?} do not match session new_peer_ids {:?}",
            payload_new_peer_ids, sorted_new_peer_ids
        )));
    }
    if payload_new_threshold != new_threshold {
        return Err(DkgError::ProtocolError(format!(
            "Reshare: current RingPayload new_threshold {} does not match session new_threshold {}",
            payload_new_threshold, new_threshold
        )));
    }
    let current_ring_sha256 = hex::encode(
        coord
            .app_state
            .bulletin
            .ring_canonical_hash(ring_id)
            .await
            .map_err(|e| {
                DkgError::Bulletin(format!(
                    "Reshare: failed to compute ring canonical hash: {}",
                    e
                ))
            })?,
    );
    let finalized_ring_sha256 = hex::encode(
        coord
            .app_state
            .bulletin
            .ring_finalized_canonical_hash(ring_id)
            .await
            .map_err(|e| {
                DkgError::Bulletin(format!(
                    "Reshare: failed to compute ring finalized canonical hash: {}",
                    e
                ))
            })?,
    );
    let chain_id = coord.app_state.bulletin.chain_id();

    coord
        .app_state
        .dkg_session_state
        .mark_reshare_signature_ready(ReshareSignatureReadyKey {
            ring_key: storage_key.to_string(),
            session_id,
            ring_id: ring_id.to_string(),
            current_ring_sha256: current_ring_sha256.clone(),
            finalized_ring_sha256: finalized_ring_sha256.clone(),
        })
        .await;

    Ok(PreparedReshareUpdate {
        sorted_new_peer_ids,
        new_committee_size,
        ring_id: ring_id.to_string(),
        sign_namespace,
        current_ring_sha256,
        finalized_ring_sha256,
        block_number_nonce: current_ring_payload.block_number_nonce,
        chain_id,
    })
}

fn reshare_new_node_id<D>(coord: &DkgCoordinator<D>, reshare_new_peer_ids: &[String]) -> u32
where
    D: CoordinatorDkg,
{
    let our_peer_id_hex = hex::encode(coord.app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);
    reshare_new_peer_ids
        .iter()
        .position(|p| extract_node_part(p) == our_node_part)
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
    session_id: u64,
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
        let err = match sign_attempt(request_id).await {
            Ok(bytes) => return Ok(bytes),
            Err(e) => e,
        };
        if attempt >= RESHARE_SIGNATURE_MAX_ATTEMPTS || !is_retryable_reshare_signature_error(&err)
        {
            return Err(err);
        }
        tracing::warn!(
            session_id = session_id,
            attempt = attempt,
            error = %err,
            "Reshare: threshold signature not ready yet, retrying"
        );
        tokio::time::sleep(retry_delay).await;
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
