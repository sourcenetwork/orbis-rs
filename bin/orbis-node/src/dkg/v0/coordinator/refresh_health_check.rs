use std::future::Future;
use std::time::Duration;

use crypto::r#trait::{CryptoDeserialize, PubPoly as PubPolyTrait, ThresholdSigner};
use crypto::{SignImpl, SignaturePoint};
use sha2::{Digest, Sha256};

use crate::constants::{REFRESH_HEALTH_CHECK_MAX_ATTEMPTS, REFRESH_HEALTH_CHECK_RETRY_DELAY};
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::network::submit_public_contribution;
use crate::dkg::v0::session_state::{
    DkgPhase, PendingRefreshHealthCheckResult, RefreshHealthCheckCandidate, TopicTaskDisposition,
};
use crate::dkg::v0::transport::{AttemptKey, DkgPublicPayload};
use crate::helpers::ring::RingConfig;
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse, SigningOptions};
use crate::sign::v0::error::SignError;
use crate::sign::v0::helpers::{
    refresh_health_check_message, refresh_health_check_peer_node_keys_sha256,
};
use crate::sign::v0::messages::{
    RefreshHealthCheckContext, RefreshHealthCheckStatement, SignContext,
    REFRESH_HEALTH_CHECK_DOMAIN,
};

use super::types::{CoordinatorDkg, CoordinatorReportSigner};
use super::{attempt_state_error, DkgCoordinator};

pub async fn run_selector<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    ring_pk_bytes: &[u8],
    candidate: &RefreshHealthCheckCandidate,
) -> Result<()>
where
    D: CoordinatorDkg + Send + Sync,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    if candidate.peer_ids.is_empty() {
        rollback_candidate(coord, attempt, &candidate.ring_key).await;
        return Err(DkgError::InvalidInput(
            "Refresh health check requires a non-empty peer set".to_string(),
        ));
    }
    if candidate.threshold == 0 || candidate.threshold > candidate.peer_ids.len() {
        rollback_candidate(coord, attempt, &candidate.ring_key).await;
        return Err(DkgError::InvalidInput(format!(
            "Refresh health check threshold {} is invalid for committee size {}",
            candidate.threshold,
            candidate.peer_ids.len()
        )));
    }

    let pub_poly_bytes = match hex::decode(&candidate.bundle.public_polynomial) {
        Ok(bytes) => bytes,
        Err(e) => {
            rollback_candidate(coord, attempt, &candidate.ring_key).await;
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
            rollback_candidate(coord, attempt, &candidate.ring_key).await;
            return Err(DkgError::Serialization(format!(
                "Refresh health check: failed to serialize signing statement: {}",
                e
            )));
        }
    };

    let sign_coordinator =
        SignCoordinator::<D, SignImpl>::with_routes(coord.app_state.clone(), coord.routes);
    let ring_config = RingConfig {
        ring_id: candidate.ring_key.clone(),
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
                SigningOptions::default(),
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

    let signature = signature_result
        .inspect_err(|error| {
            tracing::warn!(
                session_id = session_id,
                error = %error,
                "Refresh health check: diagnostic signature collection failed; broadcasting rollback"
            );
        })
        .ok();

    if let Err(e) = broadcast_result(coord, attempt, &statement, signature.clone()).await {
        tracing::warn!(
            session_id = session_id,
            error = %e,
            "Refresh health check: failed to distribute result to every peer; rolling back locally"
        );
        apply_result(coord, attempt, 1, statement, None).await?;
        return Err(e);
    }
    apply_result(coord, attempt, 1, statement, signature).await?;

    Ok(())
}

async fn broadcast_result<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    statement: &RefreshHealthCheckStatement,
    signature: Option<String>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    submit_public_contribution(
        coord,
        attempt,
        DkgPublicPayload::RefreshHealthCheckResult {
            statement: statement.clone(),
            signature,
        },
    )
    .await
}

fn is_retryable_refresh_health_check_error(error: &SignError) -> bool {
    matches!(
        error,
        SignError::ReshareInProgress | SignError::InsufficientShares { .. } | SignError::Timeout(_)
    )
}

pub async fn handle_result<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    statement: RefreshHealthCheckStatement,
    signature: Option<String>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    apply_result(coord, attempt, from_node_id, statement, signature).await?;
    Ok(())
}

pub async fn apply_pending_result_if_present<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    let result = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| state.refresh.pending_result.take())
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    let Some(result) = result else {
        return Ok(());
    };

    tracing::debug!(
        session_id = session_id,
        from_node_id = result.from_node_id,
        "Refresh health check: applying queued result after candidate was staged"
    );
    apply_result(
        coord,
        attempt,
        result.from_node_id,
        result.statement,
        result.signature,
    )
    .await
}

async fn apply_result<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    statement: RefreshHealthCheckStatement,
    signature: Option<String>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
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

    let candidate = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| state.refresh.candidate.clone())
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    let Some(candidate) = candidate else {
        let inserted = coord
            .app_state
            .dkg_session_state
            .with_attempt_state_mut(attempt, |state| {
                if state.refresh.pending_result.is_some() {
                    return false;
                }
                state.refresh.pending_result = Some(PendingRefreshHealthCheckResult {
                    from_node_id,
                    statement,
                    signature,
                });
                true
            })
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;

        tracing::debug!(
            session_id = session_id,
            from_node_id = from_node_id,
            inserted = inserted,
            "Refresh health check: result arrived before staged candidate; queued for replay"
        );
        return Ok(());
    };

    let should_promote = match signature {
        Some(signature) => verify_result_signature::<D>(&candidate, &statement, &signature)
            .inspect_err(|error| {
                tracing::warn!(
                    session_id = session_id,
                    error = %error,
                    "Refresh health check: result signature failed verification; rolling back"
                );
            })
            .is_ok(),
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
        promote_candidate(coord, attempt, candidate).await?;
    } else {
        rollback_candidate(coord, attempt, &candidate.ring_key).await;
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
    attempt: AttemptKey,
    candidate: RefreshHealthCheckCandidate,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            candidate
                .bundle
                .save_by_ring_key(&coord.app_state.local_storage, &candidate.ring_key)
                .map_err(|e| {
                    DkgError::Storage(format!(
                        "Refresh health check: failed to promote staged bundle: {}",
                        e
                    ))
                })?;
            state.refresh.candidate = None;
            state.transition_phase(DkgPhase::Phase4Complete);
            Ok::<_, DkgError>(())
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;
    coord
        .app_state
        .dkg_session_state
        .unmark_ring_pss_for_attempt(&candidate.ring_key, attempt)
        .await;
    coord
        .app_state
        .dkg_session_state
        .complete_transport_attempt(attempt, TopicTaskDisposition::DetachCurrent)
        .await;

    tracing::info!(
        session_id = session_id,
        ring_key = %candidate.ring_key,
        "Refresh health check: promoted staged RingShareBundle"
    );

    Ok(())
}

async fn rollback_candidate<D>(coord: &DkgCoordinator<D>, attempt: AttemptKey, ring_key: &str)
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| state.refresh.candidate = None)
        .await
        .ok();
    coord
        .app_state
        .dkg_session_state
        .unmark_ring_pss_for_attempt(ring_key, attempt)
        .await;
    coord.abort_attempt(attempt).await;

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
    use crate::dkg::v0::messages::SessionKind;
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
        let coord = DkgCoordinator::with_routes(Arc::new(app_state), &::network::V0);
        let session_id = 4242;
        let ring_key = "rollback-ring";

        coord
            .create_session(
                AttemptKey::test(session_id),
                1,
                1,
                1,
                DkgRole::Standard,
                |state| {
                    state.kind = SessionKind::Refresh {
                        ring_pk_hex: ring_key.to_string(),
                    };
                },
            )
            .await
            .expect("create refresh session");
        coord
            .app_state
            .dkg_session_state
            .claim_ring_pss_attempt(ring_key, AttemptKey::test(session_id))
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

        apply_result(&coord, AttemptKey::test(session_id), 1, statement, None)
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
        let coord = DkgCoordinator::with_routes(Arc::new(app_state), &::network::V0);
        let session_id = 5151;

        coord
            .create_session(
                AttemptKey::test(session_id),
                1,
                1,
                1,
                DkgRole::Standard,
                |state| {
                    state.kind = SessionKind::Refresh {
                        ring_pk_hex: "queued-ring".to_string(),
                    };
                },
            )
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

        apply_result(
            &coord,
            AttemptKey::test(session_id),
            1,
            statement.clone(),
            None,
        )
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
        let coord = DkgCoordinator::with_routes(Arc::new(app_state), &::network::V0);
        let session_id = 6161;
        let ring_key = "queued-rollback-ring";

        coord
            .create_session(
                AttemptKey::test(session_id),
                1,
                1,
                1,
                DkgRole::Standard,
                |state| {
                    state.kind = SessionKind::Refresh {
                        ring_pk_hex: ring_key.to_string(),
                    };
                },
            )
            .await
            .expect("create refresh session");
        coord
            .app_state
            .dkg_session_state
            .claim_ring_pss_attempt(ring_key, AttemptKey::test(session_id))
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
        apply_result(&coord, AttemptKey::test(session_id), 1, statement, None)
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

        apply_pending_result_if_present(&coord, AttemptKey::test(session_id))
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
        let coord = DkgCoordinator::with_routes(Arc::new(app_state), &::network::V0);
        let session_id = 7171;

        coord
            .create_session(
                AttemptKey::test(session_id),
                1,
                1,
                1,
                DkgRole::Standard,
                |state| {
                    state.kind = SessionKind::Refresh {
                        ring_pk_hex: "sender-ring".to_string(),
                    };
                },
            )
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

        let err = apply_result(&coord, AttemptKey::test(session_id), 2, statement, None)
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
