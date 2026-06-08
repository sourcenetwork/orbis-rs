use std::future::Future;
use std::time::Duration;

use crypto::r#trait::{
    CryptoDeserialize, DistKeyShare, PubPoly as PubPolyTrait, PubShare, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignImpl, SignaturePoint};
use sha2::{Digest, Sha256};

use crate::constants::{REFRESH_HEALTH_CHECK_MAX_ATTEMPTS, REFRESH_HEALTH_CHECK_RETRY_DELAY};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::session_not_found;
use crate::dkg::messages::DkgMessage;
use crate::dkg::session_state::{PendingRefreshHealthCheckResult, RefreshHealthCheckCandidate};
use crate::helpers::helpers::RingConfig;
use crate::metrics;
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::sign::error::SignError;
use crate::sign::helpers::{
    refresh_health_check_message, refresh_health_check_peer_node_keys_sha256,
};
use crate::sign::messages::{
    RefreshHealthCheckContext, RefreshHealthCheckStatement, SignContext,
    REFRESH_HEALTH_CHECK_DOMAIN,
};

use super::types::CoordinatorDkg;
use super::DkgCoordinator;

const REFRESH_HEALTH_CHECK_RESULT_SEND_ATTEMPTS: usize = 3;
const REFRESH_HEALTH_CHECK_RESULT_RETRY_DELAY: Duration = Duration::from_millis(250);

pub(in crate::dkg::coordinator) async fn run_selector<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    ring_pk_bytes: &[u8],
    candidate: &RefreshHealthCheckCandidate,
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
    if candidate.peer_ids.is_empty() {
        rollback_candidate(coord, session_id, &candidate.ring_key).await;
        return Err(DkgError::InvalidInput(
            "Refresh health check requires a non-empty peer set".to_string(),
        ));
    }
    if candidate.threshold == 0 || candidate.threshold > candidate.peer_ids.len() {
        rollback_candidate(coord, session_id, &candidate.ring_key).await;
        return Err(DkgError::InvalidInput(format!(
            "Refresh health check threshold {} is invalid for committee size {}",
            candidate.threshold,
            candidate.peer_ids.len()
        )));
    }

    let pub_poly_bytes = match hex::decode(&candidate.bundle.public_polynomial) {
        Ok(bytes) => bytes,
        Err(e) => {
            rollback_candidate(coord, session_id, &candidate.ring_key).await;
            return Err(DkgError::Deserialization(format!(
                "Refresh health check: failed to decode staged polynomial: {}",
                e
            )));
        }
    };
    let public_polynomial_sha256 = hex::encode(Sha256::digest(pub_poly_bytes));
    let statement = RefreshHealthCheckStatement {
        domain: REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
        session_id,
        ring_pk: candidate.ring_pk_hex.clone(),
        public_polynomial_sha256,
        peer_node_keys_sha256: refresh_health_check_peer_node_keys_sha256(
            &candidate.peer_node_keys,
        ),
        threshold: candidate.threshold as u32,
        total_participants: candidate.peer_ids.len() as u32,
    };
    let message_to_sign = match refresh_health_check_message(&statement) {
        Ok(message) => message,
        Err(e) => {
            rollback_candidate(coord, session_id, &candidate.ring_key).await;
            return Err(DkgError::Serialization(format!(
                "Refresh health check: failed to serialize signing statement: {}",
                e
            )));
        }
    };

    let sign_coordinator = SignCoordinator::<D, SignImpl>::new(coord.app_state.clone());
    let ring_config = RingConfig {
        ring_pk_bytes: ring_pk_bytes.to_vec(),
        peer_ids: candidate.peer_ids.clone(),
        peer_node_keys: candidate.peer_node_keys.clone(),
        threshold: candidate.threshold,
        total_participants: candidate.peer_ids.len(),
        public_polynomial_hex: candidate.bundle.public_polynomial.clone(),
    };
    let sign_context = SignContext::RefreshHealthCheck(Box::new(RefreshHealthCheckContext {
        statement: statement.clone(),
    }));

    let signature_result = collect_refresh_health_check_signature_with_retry(
        session_id,
        REFRESH_HEALTH_CHECK_RETRY_DELAY,
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
    .and_then(|response_bytes| {
        let sign_response: SignResponse = serde_json::from_slice(&response_bytes).map_err(|e| {
            SignError::Deserialization(format!(
                "Refresh health check: failed to parse diagnostic signature response: {}",
                e
            ))
        })?;
        if sign_response.signature.is_empty() {
            return Err(SignError::Crypto(
                "Refresh health check: diagnostic signature response was empty".to_string(),
            ));
        }
        Ok(sign_response.signature)
    });

    let signature = match signature_result {
        Ok(signature) => Some(signature),
        Err(e) => {
            tracing::warn!(
                session_id = session_id,
                error = %e,
                "Refresh health check: diagnostic signature collection failed; broadcasting rollback"
            );
            None
        }
    };

    if let Err(e) = broadcast_result(
        coord,
        session_id,
        &candidate.peer_ids,
        &statement,
        signature.clone(),
    )
    .await
    {
        tracing::warn!(
            session_id = session_id,
            error = %e,
            "Refresh health check: failed to distribute result to every peer; rolling back locally"
        );
        apply_result(coord, session_id, 1, statement, None).await?;
        return Err(e);
    }
    apply_result(coord, session_id, 1, statement, signature).await?;

    Ok(())
}

async fn broadcast_result<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    peer_ids: &[String],
    statement: &RefreshHealthCheckStatement,
    signature: Option<String>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    for peer_id in peer_ids {
        if crate::helpers::helpers::is_self_peer_id(&coord.app_state.network, peer_id) {
            continue;
        }

        let mut last_error = None;
        for attempt in 1..=REFRESH_HEALTH_CHECK_RESULT_SEND_ATTEMPTS {
            let msg = DkgMessage::RefreshHealthCheckResult {
                session_id,
                from_node_id: 1,
                statement: statement.clone(),
                signature: signature.clone(),
            };
            match coord
                .send_message_to_peer(peer_id, msg, Some(session_id))
                .await
            {
                Ok(()) => {
                    last_error = None;
                    break;
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                    tracing::warn!(
                        session_id = session_id,
                        peer_id = %peer_id,
                        attempt = attempt,
                        error = %e,
                        "Refresh health check: failed to deliver result"
                    );
                    if attempt < REFRESH_HEALTH_CHECK_RESULT_SEND_ATTEMPTS {
                        tokio::time::sleep(REFRESH_HEALTH_CHECK_RESULT_RETRY_DELAY).await;
                    }
                }
            }
        }

        if let Some(error) = last_error {
            return Err(DkgError::NetworkCommunication(format!(
                "Refresh health check: failed to deliver result to {}: {}",
                peer_id, error
            )));
        }
    }

    Ok(())
}

fn is_retryable_refresh_health_check_error(error: &SignError) -> bool {
    matches!(
        error,
        SignError::ReshareInProgress | SignError::InsufficientShares { .. } | SignError::Timeout(_)
    )
}

pub(in crate::dkg::coordinator) async fn handle_result<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
    statement: RefreshHealthCheckStatement,
    signature: Option<String>,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
{
    apply_result(coord, session_id, from_node_id, statement, signature).await?;
    Ok(None)
}

pub(in crate::dkg::coordinator) async fn apply_pending_result_if_present<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let Some(result) = coord
        .app_state
        .dkg_session_state
        .take_pending_refresh_health_check_result(&session_id)
        .await
    else {
        return Ok(());
    };

    tracing::debug!(
        session_id = session_id,
        from_node_id = result.from_node_id,
        "Refresh health check: applying queued result after candidate was staged"
    );
    apply_result(
        coord,
        session_id,
        result.from_node_id,
        result.statement,
        result.signature,
    )
    .await
}

async fn apply_result<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
    statement: RefreshHealthCheckStatement,
    signature: Option<String>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if from_node_id != 1 {
        return Err(DkgError::Unauthorized(format!(
            "RefreshHealthCheckResult must come from node 1, got {}",
            from_node_id
        )));
    }
    if statement.session_id != session_id {
        return Err(DkgError::Unauthorized(format!(
            "Refresh health-check statement session_id {} does not match routed session {}",
            statement.session_id, session_id
        )));
    }

    let Some(candidate) = coord
        .app_state
        .dkg_session_state
        .refresh_health_check_candidate(&session_id)
        .await
    else {
        let inserted = coord
            .app_state
            .dkg_session_state
            .store_pending_refresh_health_check_result(
                &session_id,
                PendingRefreshHealthCheckResult {
                    from_node_id,
                    statement,
                    signature,
                },
            )
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        tracing::debug!(
            session_id = session_id,
            from_node_id = from_node_id,
            inserted = inserted,
            "Refresh health check: result arrived before staged candidate; queued for replay"
        );
        return Ok(());
    };

    let should_promote = match signature {
        Some(signature) => match verify_result_signature::<D>(&candidate, &statement, &signature) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    session_id = session_id,
                    error = %e,
                    "Refresh health check: result signature failed verification; rolling back"
                );
                false
            }
        },
        None => {
            tracing::warn!(
                session_id = session_id,
                "Refresh health check: selector reported failure; rolling back"
            );
            false
        }
    };
    // a partial broadcast failure can leave peers in inconsistent staged state;
    // this is tolerated because the health check is diagnostic and the underlying key material is already persisted independently
    if should_promote {
        promote_candidate(coord, session_id, candidate).await?;
    } else {
        rollback_candidate(coord, session_id, &candidate.ring_key).await;
    }

    Ok(())
}

fn verify_result_signature<D>(
    candidate: &RefreshHealthCheckCandidate,
    statement: &RefreshHealthCheckStatement,
    signature_hex: &str,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if statement.domain != REFRESH_HEALTH_CHECK_DOMAIN
        || statement.ring_pk != candidate.ring_pk_hex
        || statement.threshold as usize != candidate.threshold
        || statement.total_participants as usize != candidate.peer_ids.len()
        || statement.peer_node_keys_sha256
            != refresh_health_check_peer_node_keys_sha256(&candidate.peer_node_keys)
    {
        return Err(DkgError::Unauthorized(
            "Refresh health-check statement does not match staged candidate".to_string(),
        ));
    }

    let pub_poly_bytes = hex::decode(&candidate.bundle.public_polynomial).map_err(|e| {
        DkgError::Deserialization(format!(
            "Refresh health check: failed to decode staged public polynomial: {}",
            e
        ))
    })?;
    if statement.public_polynomial_sha256 != hex::encode(Sha256::digest(&pub_poly_bytes)) {
        return Err(DkgError::Unauthorized(
            "Refresh health-check polynomial hash does not match staged candidate".to_string(),
        ));
    }

    let message = refresh_health_check_message(statement).map_err(|e| {
        DkgError::Serialization(format!(
            "Refresh health check: failed to serialize statement: {}",
            e
        ))
    })?;
    let signature_bytes = hex::decode(signature_hex).map_err(|e| {
        DkgError::Deserialization(format!(
            "Refresh health check: failed to decode signature hex: {}",
            e
        ))
    })?;
    let signature = SignaturePoint::from_bytes(&signature_bytes).map_err(|e| {
        DkgError::Deserialization(format!(
            "Refresh health check: failed to deserialize signature: {}",
            e
        ))
    })?;
    let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
        DkgError::Deserialization(format!(
            "Refresh health check: failed to deserialize staged public polynomial: {}",
            e
        ))
    })?;
    let verify_pk = pub_poly.eval(0);
    let signer = SignImpl::new();
    signer
        .verify(&verify_pk, &message, &signature)
        .map_err(|e| {
            DkgError::Crypto(format!(
                "Refresh health check: diagnostic signature did not verify: {}",
                e
            ))
        })?;

    Ok(())
}

async fn promote_candidate<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    candidate: RefreshHealthCheckCandidate,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    candidate
        .bundle
        .save_by_ring_key(&coord.app_state.local_storage, &candidate.ring_key)
        .map_err(|e| {
            DkgError::Storage(format!(
                "Refresh health check: failed to promote staged bundle: {}",
                e
            ))
        })?;
    coord
        .app_state
        .dkg_session_state
        .clear_refresh_health_check_candidate(&session_id)
        .await;
    coord
        .app_state
        .dkg_session_state
        .unmark_ring_pss(&candidate.ring_key)
        .await;
    coord.remove_session(session_id).await;
    metrics::record_dkg_session_completed();
    metrics::record_refresh_session_completed();

    tracing::info!(
        session_id = session_id,
        ring_key = %candidate.ring_key,
        "Refresh health check: promoted staged RingShareBundle"
    );

    Ok(())
}

async fn rollback_candidate<D>(coord: &DkgCoordinator<D>, session_id: u128, ring_key: &str)
where
    D: CoordinatorDkg,
{
    coord
        .app_state
        .dkg_session_state
        .clear_refresh_health_check_candidate(&session_id)
        .await;
    coord
        .app_state
        .dkg_session_state
        .unmark_ring_pss(ring_key)
        .await;
    coord.remove_session(session_id).await;
    metrics::record_refresh_session_failed();

    tracing::warn!(
        session_id = session_id,
        ring_key = %ring_key,
        "Refresh health check: discarded staged RingShareBundle"
    );
}

async fn collect_refresh_health_check_signature_with_retry<F, Fut>(
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
        let request_id = format!("refresh-health-check-{}-{}", session_id, attempt);
        let result = sign_attempt(request_id).await;
        if let Err(error) = &result {
            if attempt < REFRESH_HEALTH_CHECK_MAX_ATTEMPTS
                && is_retryable_refresh_health_check_error(error)
            {
                tracing::warn!(
                    session_id = session_id,
                    attempt = attempt,
                    error = %error,
                    "Refresh health check: diagnostic signature not ready yet, retrying"
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
    use crate::dkg::messages::SessionKind;
    use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_default, test_db_path};
    use crate::ring_state::RingShareBundle;
    use crypto::r#trait::DkgRole;
    use std::cell::RefCell;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    #[tokio::test]
    async fn refresh_health_check_retry_uses_unique_request_ids() {
        let calls = RefCell::new(Vec::new());
        let response = collect_refresh_health_check_signature_with_retry(
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
                "refresh-health-check-42-1".to_string(),
                "refresh-health-check-42-2".to_string(),
                "refresh-health-check-42-3".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn refresh_health_check_failure_discards_staged_bundle() {
        let db_name = "refresh_health_check_failure_discards_staged_bundle";
        let db_path = test_db_path(db_name);
        let app_state = create_test_app_state_default(db_name).await;
        let coord = DkgCoordinator::new(Arc::new(app_state));
        let session_id = 4242;
        let ring_key = "rollback-ring";

        coord
            .create_session(session_id, 1, 1, 1, DkgRole::Standard, |state| {
                state.kind = SessionKind::Refresh {
                    ring_pk_hex: ring_key.to_string(),
                };
            })
            .await
            .expect("create refresh session");
        coord
            .app_state
            .dkg_session_state
            .claim_ring_pss_session(ring_key, session_id)
            .await;

        let old_bundle = RingShareBundle {
            share_bytes: Zeroizing::new(vec![1]),
            public_polynomial: "old-polynomial".to_string(),
            last_pss: 10,
        };
        old_bundle
            .save_by_ring_key(&coord.app_state.local_storage, ring_key)
            .expect("save old bundle");

        coord
            .app_state
            .dkg_session_state
            .set_refresh_health_check_candidate(
                &session_id,
                RefreshHealthCheckCandidate {
                    ring_key: ring_key.to_string(),
                    ring_pk_hex: "00".to_string(),
                    bundle: RingShareBundle {
                        share_bytes: Zeroizing::new(vec![2]),
                        public_polynomial: "staged-polynomial".to_string(),
                        last_pss: 20,
                    },
                    peer_node_keys: vec!["node-1".to_string()],
                    peer_ids: vec!["peer-1".to_string()],
                    threshold: 1,
                },
            )
            .await;

        let statement = RefreshHealthCheckStatement {
            domain: REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
            session_id,
            ring_pk: "00".to_string(),
            public_polynomial_sha256: String::new(),
            peer_node_keys_sha256: String::new(),
            threshold: 1,
            total_participants: 1,
        };

        apply_result(&coord, session_id, 1, statement, None)
            .await
            .expect("rollback result should apply");

        let stored = RingShareBundle::load_by_ring_key(&coord.app_state.local_storage, ring_key)
            .expect("old bundle should remain active");
        assert_eq!(stored.public_polynomial, "old-polynomial");
        assert!(
            coord
                .app_state
                .dkg_session_state
                .refresh_health_check_candidate(&session_id)
                .await
                .is_none(),
            "staged bundle should be discarded"
        );
        assert!(
            !coord
                .app_state
                .dkg_session_state
                .session_exists(&session_id)
                .await,
            "refresh session should be removed"
        );
        assert!(
            !coord
                .app_state
                .dkg_session_state
                .is_ring_pss_active(ring_key)
                .await,
            "PSS claim should be released"
        );

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn refresh_health_check_result_before_candidate_is_queued() {
        let db_name = "refresh_health_check_result_before_candidate_is_queued";
        let db_path = test_db_path(db_name);
        let app_state = create_test_app_state_default(db_name).await;
        let coord = DkgCoordinator::new(Arc::new(app_state));
        let session_id = 5151;

        coord
            .create_session(session_id, 1, 1, 1, DkgRole::Standard, |state| {
                state.kind = SessionKind::Refresh {
                    ring_pk_hex: "queued-ring".to_string(),
                };
            })
            .await
            .expect("create refresh session");

        let statement = RefreshHealthCheckStatement {
            domain: REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
            session_id,
            ring_pk: "00".to_string(),
            public_polynomial_sha256: String::new(),
            peer_node_keys_sha256: String::new(),
            threshold: 1,
            total_participants: 1,
        };

        apply_result(&coord, session_id, 1, statement.clone(), None)
            .await
            .expect("early result should queue");

        let queued = coord
            .app_state
            .dkg_session_state
            .take_pending_refresh_health_check_result(&session_id)
            .await
            .expect("early result should be queued");
        assert_eq!(queued.from_node_id, 1);
        assert_eq!(queued.statement.session_id, statement.session_id);
        assert!(queued.signature.is_none());

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn queued_refresh_health_check_rollback_drains_after_candidate_is_staged() {
        let db_name = "queued_refresh_health_check_rollback_drains_after_candidate_is_staged";
        let db_path = test_db_path(db_name);
        let app_state = create_test_app_state_default(db_name).await;
        let coord = DkgCoordinator::new(Arc::new(app_state));
        let session_id = 6161;
        let ring_key = "queued-rollback-ring";

        coord
            .create_session(session_id, 1, 1, 1, DkgRole::Standard, |state| {
                state.kind = SessionKind::Refresh {
                    ring_pk_hex: ring_key.to_string(),
                };
            })
            .await
            .expect("create refresh session");
        coord
            .app_state
            .dkg_session_state
            .claim_ring_pss_session(ring_key, session_id)
            .await;

        let old_bundle = RingShareBundle {
            share_bytes: Zeroizing::new(vec![1]),
            public_polynomial: "old-polynomial".to_string(),
            last_pss: 10,
        };
        old_bundle
            .save_by_ring_key(&coord.app_state.local_storage, ring_key)
            .expect("save old bundle");

        let statement = RefreshHealthCheckStatement {
            domain: REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
            session_id,
            ring_pk: "00".to_string(),
            public_polynomial_sha256: String::new(),
            peer_node_keys_sha256: String::new(),
            threshold: 1,
            total_participants: 1,
        };
        apply_result(&coord, session_id, 1, statement, None)
            .await
            .expect("early rollback result should queue");

        coord
            .app_state
            .dkg_session_state
            .set_refresh_health_check_candidate(
                &session_id,
                RefreshHealthCheckCandidate {
                    ring_key: ring_key.to_string(),
                    ring_pk_hex: "00".to_string(),
                    bundle: RingShareBundle {
                        share_bytes: Zeroizing::new(vec![2]),
                        public_polynomial: "staged-polynomial".to_string(),
                        last_pss: 20,
                    },
                    peer_node_keys: vec!["node-1".to_string()],
                    peer_ids: vec!["peer-1".to_string()],
                    threshold: 1,
                },
            )
            .await;

        apply_pending_result_if_present(&coord, session_id)
            .await
            .expect("queued rollback should apply");

        let stored = RingShareBundle::load_by_ring_key(&coord.app_state.local_storage, ring_key)
            .expect("old bundle should remain active");
        assert_eq!(stored.public_polynomial, "old-polynomial");
        assert!(
            !coord
                .app_state
                .dkg_session_state
                .session_exists(&session_id)
                .await,
            "refresh session should be removed after queued rollback"
        );
        assert!(
            !coord
                .app_state
                .dkg_session_state
                .is_ring_pss_active(ring_key)
                .await,
            "PSS claim should be released after queued rollback"
        );

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn refresh_health_check_result_rejects_invalid_sender_before_queueing() {
        let db_name = "refresh_health_check_result_rejects_invalid_sender_before_queueing";
        let db_path = test_db_path(db_name);
        let app_state = create_test_app_state_default(db_name).await;
        let coord = DkgCoordinator::new(Arc::new(app_state));
        let session_id = 7171;

        coord
            .create_session(session_id, 1, 1, 1, DkgRole::Standard, |state| {
                state.kind = SessionKind::Refresh {
                    ring_pk_hex: "sender-ring".to_string(),
                };
            })
            .await
            .expect("create refresh session");

        let statement = RefreshHealthCheckStatement {
            domain: REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
            session_id,
            ring_pk: "00".to_string(),
            public_polynomial_sha256: String::new(),
            peer_node_keys_sha256: String::new(),
            threshold: 1,
            total_participants: 1,
        };

        let err = apply_result(&coord, session_id, 2, statement, None)
            .await
            .expect_err("non-selector result should be rejected");
        assert!(matches!(err, DkgError::Unauthorized(_)));
        assert!(
            coord
                .app_state
                .dkg_session_state
                .take_pending_refresh_health_check_result(&session_id)
                .await
                .is_none(),
            "invalid sender should not queue a result"
        );

        cleanup_db(&db_path);
    }
}
