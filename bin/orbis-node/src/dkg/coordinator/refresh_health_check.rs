use std::future::Future;
use std::time::Duration;

use crypto::r#trait::{DistKeyShare, PubShare, ThresholdSigner};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignImpl, SignaturePoint};
use sha2::{Digest, Sha256};

use crate::constants::{REFRESH_HEALTH_CHECK_MAX_ATTEMPTS, REFRESH_HEALTH_CHECK_RETRY_DELAY};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::messages::SessionKind;
use crate::helpers::helpers::RingConfig;
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::sign::error::SignError;
use crate::sign::helpers::{refresh_health_check_message, refresh_health_check_peer_ids_sha256};
use crate::sign::messages::{
    RefreshHealthCheckContext, RefreshHealthCheckStatement, SignContext,
    REFRESH_HEALTH_CHECK_DOMAIN,
};

use super::types::CoordinatorDkg;
use super::DkgCoordinator;

pub(in crate::dkg::coordinator) async fn run_if_refresh_selector<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    kind: &SessionKind,
    node_id: u32,
    ring_pk_bytes: &[u8],
    pub_poly_bytes: &[u8],
    peer_ids: &[String],
    threshold: usize,
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
    if !matches!(kind, SessionKind::Refresh { .. }) || node_id != 1 {
        return Ok(());
    }
    if peer_ids.is_empty() {
        return Err(DkgError::InvalidInput(
            "Refresh health check requires a non-empty peer set".to_string(),
        ));
    }
    if threshold == 0 || threshold > peer_ids.len() {
        return Err(DkgError::InvalidInput(format!(
            "Refresh health check threshold {} is invalid for committee size {}",
            threshold,
            peer_ids.len()
        )));
    }

    let public_polynomial_sha256 = hex::encode(Sha256::digest(pub_poly_bytes));
    let statement = RefreshHealthCheckStatement {
        domain: REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
        session_id,
        ring_pk: hex::encode(ring_pk_bytes),
        public_polynomial_sha256,
        peer_ids_sha256: refresh_health_check_peer_ids_sha256(peer_ids),
        threshold: threshold as u32,
        total_participants: peer_ids.len() as u32,
    };
    let message_to_sign = refresh_health_check_message(&statement).map_err(|e| {
        DkgError::Serialization(format!(
            "Refresh health check: failed to serialize signing statement: {}",
            e
        ))
    })?;

    let sign_coordinator = SignCoordinator::<D, SignImpl>::new(coord.app_state.clone());
    let ring_config = RingConfig {
        ring_pk_bytes: ring_pk_bytes.to_vec(),
        peer_ids: peer_ids.to_vec(),
        threshold,
        total_participants: peer_ids.len(),
        public_polynomial_hex: hex::encode(pub_poly_bytes),
    };
    let sign_context =
        SignContext::RefreshHealthCheck(Box::new(RefreshHealthCheckContext { statement }));

    let response_bytes = collect_refresh_health_check_signature_with_retry(
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
    .map_err(|e| {
        DkgError::Crypto(format!(
            "Refresh health check: failed to collect diagnostic threshold signature: {}",
            e
        ))
    })?;
    let sign_response: SignResponse = serde_json::from_slice(&response_bytes).map_err(|e| {
        DkgError::Deserialization(format!(
            "Refresh health check: failed to parse diagnostic signature response: {}",
            e
        ))
    })?;
    if sign_response.signature.is_empty() {
        return Err(DkgError::Crypto(
            "Refresh health check: diagnostic signature response was empty".to_string(),
        ));
    }

    tracing::info!(
        session_id = session_id,
        threshold = threshold,
        committee_size = peer_ids.len(),
        signature_len = sign_response.signature.len(),
        "Refresh health check: successfully produced diagnostic threshold signature"
    );

    Ok(())
}

fn is_retryable_refresh_health_check_error(error: &SignError) -> bool {
    matches!(
        error,
        SignError::ReshareInProgress | SignError::InsufficientShares { .. } | SignError::Timeout(_)
    )
}

async fn collect_refresh_health_check_signature_with_retry<F, Fut>(
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
        let request_id = format!("refresh-health-check-{}-{}", session_id, attempt);
        let err = match sign_attempt(request_id).await {
            Ok(bytes) => return Ok(bytes),
            Err(e) => e,
        };
        if attempt >= REFRESH_HEALTH_CHECK_MAX_ATTEMPTS
            || !is_retryable_refresh_health_check_error(&err)
        {
            return Err(err);
        }
        tracing::warn!(
            session_id = session_id,
            attempt = attempt,
            error = %err,
            "Refresh health check: diagnostic signature not ready yet, retrying"
        );
        tokio::time::sleep(retry_delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

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
}
