//! A forged, provably-bad DKG-refresh share+signature submitted *as* the
//! accused node (using that node's own real signing key, read directly out
//! of its in-process local storage -- the reason this is an in-process
//! test at all) must be accepted as a valid `invalid_crypto_response`
//! report and assess exactly one demerit.
//!
//! Harness-unification migration, PR 6: migrated off `concurrent.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one.
//! The original Cosmos-only pass/fail signal (`ReportEventSubscription`, a
//! Tendermint-WS subscription with no native equivalent) is replaced with
//! polling [`super::live_node::LiveNodeNetwork::read_node_demerits`] --
//! the same dual-backend simplification the `reporting.rs` migration
//! established (trading per-report metadata assertions for a portable
//! demerit-count check; the thing actually under test -- a forged report
//! is accepted and demerits the right node -- is preserved exactly).
//! Fully dual-backend -- no `#[ignore]` needed.

use super::live_node::{setup_ring, LiveNodeNetwork};
use bulletin::r#trait::RingPayload;
use common::blockchain::sign_node_message_with_hex_key;
use crypto::{
    r#trait::{CryptoDeserialize, Dkg, DkgMode, DkgRole},
    CryptoSerialize, DkgImpl, ScalarField,
};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(all(feature = "integration-test", feature = "cosmos"))]
use crate::{
    app_state::AppState,
    dkg::v0::helpers::serialize_commitment_coefficients,
    reporting::v0::{
        observation::{InvalidCryptoResponseObservation, ReportObservation},
        queue_report,
        types::{
            ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DkgShareStatement,
            InvalidCryptoResponse, CHAIN_BLOCK_GRACE_SECS, DKG_COMMITMENT_DOMAIN, DKG_SHARE_DOMAIN,
        },
    },
};
#[cfg(all(feature = "integration-test", feature = "native"))]
use crate::{
    app_state::AppState,
    dkg::v0::helpers::serialize_commitment_coefficients,
    reporting::v0::{
        observation::{InvalidCryptoResponseObservation, ReportObservation},
        queue_report,
        types::{
            ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DkgShareStatement,
            InvalidCryptoResponse, CHAIN_BLOCK_GRACE_SECS, DKG_COMMITMENT_DOMAIN, DKG_SHARE_DOMAIN,
        },
    },
};

fn sorted_node_id(node_key: &str, peer_node_keys: &[String]) -> u32 {
    let mut sorted_node_keys = peer_node_keys.to_vec();
    sorted_node_keys.sort();
    sorted_node_keys
        .iter()
        .position(|candidate| candidate == node_key)
        .map(|index| index as u32 + 1)
        .expect("node key in ring")
}

#[allow(clippy::too_many_arguments)]
fn signed_bad_refresh_dkg_share_observation(
    chain_id: String,
    ring_id: String,
    ring: &RingPayload,
    accused_node_key: String,
    accused_peer_id: String,
    accused_app_state: &AppState<DkgImpl>,
) -> InvalidCryptoResponseObservation {
    let from_node_id = sorted_node_id(&accused_node_key, &ring.peer_node_keys);
    let to_node_id = (1..=ring.peer_node_keys.len() as u32)
        .find(|candidate| {
            *candidate != from_node_id
                && ring
                    .peer_node_keys
                    .get(candidate.saturating_sub(1) as usize)
                    .is_some_and(|node_key| node_key != &accused_node_key)
        })
        .expect("non-accused receiver");
    let receiver_node_key = ring.peer_node_keys[to_node_id.saturating_sub(1) as usize].clone();

    let dkg_session_id = 424_242_171_u128;
    let request_id = dkg_session_id.to_string();
    let mut dealer = DkgImpl::new(
        from_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        dkg_session_id,
        DkgRole::Standard,
    )
    .expect("create DKG dealer");
    dealer
        .generate_polynomial(DkgMode::Refresh)
        .expect("generate refresh polynomial");
    let commitment =
        serialize_commitment_coefficients(&dealer.commitment().coefficients).expect("commitment");
    let share = dealer
        .generate_shares()
        .expect("generate shares")
        .into_iter()
        .find(|share| share.to_id == to_node_id)
        .expect("share for receiver");
    let share_value = <ScalarField as CryptoSerialize>::to_bytes(&share.value).expect("share");
    let mut bad_share_value = ScalarField::from_bytes(&share_value).expect("deserialize share");
    bad_share_value += ScalarField::from(1_u64);
    let bad_share_value =
        <ScalarField as CryptoSerialize>::to_bytes(&bad_share_value).expect("bad share");
    assert_ne!(share_value, bad_share_value);

    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();
    let commitment_statement = DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: chain_id.clone(),
        ring_id: ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: network::V0.version,
        request_id: request_id.clone(),
        signed_at: signed_at - 1,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        commitment,
        session_nonce: [0u8; 16],
        attempt_id: [9; 32],
        crypto_backend: DkgImpl::name(),
    };
    let signing_key = accused_app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .expect("read node signing key")
        .expect("node signing key exists");
    let signing_key_hex = String::from_utf8(signing_key.to_vec()).expect("signing key hex");
    let commitment_signature =
        sign_node_message_with_hex_key(&signing_key_hex, &commitment_statement.canonical_bytes())
            .expect("sign DKG commitment evidence");
    let statement = DkgShareStatement {
        domain: DKG_SHARE_DOMAIN.to_string(),
        chain_id,
        ring_id: ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: network::V0.version,
        request_id,
        signed_at,
        responder_node_key: accused_node_key.clone(),
        receiver_node_key,
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        to_node_id,
        commitment_statement,
        commitment_signature,
        share_value: bad_share_value,
        nonce: share.nonce,
        crypto_backend: DkgImpl::name(),
    };
    let response_signature =
        sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes())
            .expect("sign DKG share evidence");
    let observed_at = signed_at - CHAIN_BLOCK_GRACE_SECS;
    InvalidCryptoResponseObservation {
        ring_id,
        accused_node_key,
        accused_peer_id,
        observed_at,
        inline_document: None,
        pet_blind_context: None,
        pet_blind_certificate: None,
        evidence: InvalidCryptoResponse::DkgShare {
            statement: Box::new(statement),
            response_signature,
        },
    }
}

async fn wait_for_demerits(
    net: &LiveNodeNetwork,
    ring_id: &str,
    node_key: &str,
    expected: u64,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let demerits = net.read_node_demerits(ring_id, node_key).await;
        if demerits >= expected {
            assert_eq!(
                demerits, expected,
                "unexpected demerit count for {node_key}"
            );
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {node_key} to accrue {expected} demerit(s), currently {demerits}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_vera_accepts_invalid_crypto_dkg_share_report_from_live_nodes() {
    let net = super::live_node::setup_live_node_network(3, "reporting_dkg_share_vera").await;
    let endpoint = net.node(0).grpc_endpoint.clone();

    let (ring_pk_hex, ring_id) = setup_ring(&net, &endpoint, 2).await;
    super::live_node::wait_for_live_ring_states(
        &[net.node(0), net.node(1), net.node(2)],
        &ring_pk_hex,
    )
    .await;
    let ring = net.read_ring_payload(&ring_id).await;

    let accused_node_key = net.node(2).node_key.clone();
    let chain_id = net.node(0).app_state.bulletin.chain_id();
    let observation = signed_bad_refresh_dkg_share_observation(
        chain_id,
        ring_id.clone(),
        &ring,
        accused_node_key.clone(),
        net.node(2).peer_addr.clone(),
        &net.node(2).app_state,
    );

    assert!(
        queue_report::<DkgImpl, crypto::SignImpl>(
            net.node(0).app_state.clone(),
            &network::V0,
            ReportObservation::InvalidCryptoResponse(Box::new(observation)),
        )
        .await
        .expect("queue invalid DKG-share report"),
        "report should be queued"
    );
    net.node(0).app_state.reporting_state.shutdown().await;

    wait_for_demerits(
        &net,
        &ring_id,
        &accused_node_key,
        1,
        Duration::from_secs(120),
    )
    .await;
}
