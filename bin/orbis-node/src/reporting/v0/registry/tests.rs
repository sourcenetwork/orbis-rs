use super::*;
use crate::dkg::v0::helpers::serialize_commitment_coefficients;
use crate::reporting::v0::observation::{
    InvalidCryptoResponseObservation, OfflineObservation, ReportObservation,
};
use crate::reporting::v0::types::{
    CommitteeScope, DkgCommitmentStatement, DkgShareStatement, InvalidCryptoResponse, NodeOffline,
    PreReencryptResponseStatement, RelayRequestStatement, ReportedDocumentEvidence,
    SignResponseStatement, DKG_COMMITMENT_DOMAIN, DKG_SHARE_DOMAIN,
    INVALID_CRYPTO_RESPONSE_REPORT_TYPE, PRE_REENCRYPT_RESPONSE_DOMAIN, RELAY_REQUEST_DOMAIN,
    REPORT_DOMAIN, REPORT_TTL_SECS, SIGN_RESPONSE_DOMAIN, UNAUTHORIZED_REQUEST_REPORT_TYPE,
};
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{BulletinPost, UpgradeInfo};
use crypto::r#trait::{CryptoSerialize, DkgMode, DkgRole};

fn ring_fixture(threshold: u32) -> RingPayload {
    RingPayload {
        ring_pk: "pk".to_string(),
        peer_node_keys: vec![
            "reporter".to_string(),
            "accused".to_string(),
            "validator".to_string(),
        ],
        threshold,
        pss_interval: 86_400,
        upgrade_info: UpgradeInfo {
            current_version: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn envelope(ring: &RingPayload) -> ReportEnvelope {
    ReportEnvelope {
        domain: REPORT_DOMAIN.to_string(),
        report_type: NODE_OFFLINE_REPORT_TYPE.to_string(),
        chain_id: "chain".to_string(),
        ring_id: "ring".to_string(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        reporter_node_key: "reporter".to_string(),
        accused_node_key: "accused".to_string(),
        accused_peer_id: "aa".repeat(32),
        observed_at: 100,
        expires_at: 100 + REPORT_TTL_SECS,
        payload: NodeOffline {
            origin_protocol: "pre".to_string(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
        }
        .canonical_bytes(),
        session_id: "session-1".to_string(),
    }
}

fn payload(report: &ReportEnvelope) -> NodeOffline {
    NodeOffline::from_canonical_bytes(&report.payload).unwrap()
}

fn offline_observation() -> OfflineObservation {
    OfflineObservation {
        ring_id: "ring".to_string(),
        accused_node_key: "accused".to_string(),
        accused_peer_id: "aa".repeat(32),
        origin_protocol: "pre".to_string(),
        origin_protocol_version: 0,
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        observed_at: 100,
        session_id: "session-1".to_string(),
    }
}

fn pre_invalid_observation() -> InvalidCryptoResponseObservation {
    InvalidCryptoResponseObservation {
        ring_id: "ring".to_string(),
        accused_node_key: "accused".to_string(),
        accused_peer_id: "aa".repeat(32),
        observed_at: 100,
        inline_document: None,
        evidence: InvalidCryptoResponse::Pre {
            statement: PreReencryptResponseStatement {
                domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
                chain_id: "chain".to_string(),
                ring_id: "ring".to_string(),
                ring_pk: "pk".to_string(),
                ring_state_sha256: "00".repeat(32),
                protocol_version: 0,
                request_id: "pre-request-1".to_string(),
                signed_at: 110,
                responder_node_key: "accused".to_string(),
                origin_protocol: "pre".to_string(),
                object_id: "object".to_string(),
                rdr_pk: vec![1],
                derivation: None,
                from_node_id: 2,
                share: vec![2],
                challenge: vec![3],
                proof: vec![4],
                crypto_backend: "elgamal/test".to_string(),
                timestamp: None,
                document_inline: false,
            },
            response_signature: vec![5; 64],
        },
    }
}

fn sign_invalid_observation() -> InvalidCryptoResponseObservation {
    InvalidCryptoResponseObservation {
        ring_id: "ring".to_string(),
        accused_node_key: "accused".to_string(),
        accused_peer_id: "aa".repeat(32),
        observed_at: 100,
        inline_document: None,
        evidence: InvalidCryptoResponse::Sign {
            statement: SignResponseStatement {
                domain: SIGN_RESPONSE_DOMAIN.to_string(),
                chain_id: "chain".to_string(),
                ring_id: "ring".to_string(),
                ring_pk: "pk".to_string(),
                ring_state_sha256: "00".repeat(32),
                protocol_version: 0,
                request_id: "sign-request-1".to_string(),
                signed_at: 110,
                responder_node_key: "accused".to_string(),
                origin_protocol: "sign".to_string(),
                accused_committee_scope: CommitteeScope::Current,
                signing_committee_scope: CommitteeScope::Current,
                from_node_id: 2,
                message: vec![1],
                signing_commitments: Vec::new(),
                derivation: None,
                metadata: None,
                sig_share: vec![2],
                crypto_backend: "threshold-sign/test".to_string(),
            },
            response_signature: vec![5; 64],
        },
    }
}

fn relay_request_statement(
    ring: &RingPayload,
    chain_id: String,
    signed_at: u64,
) -> RelayRequestStatement {
    RelayRequestStatement {
        domain: RELAY_REQUEST_DOMAIN.to_string(),
        chain_id,
        ring_id: "ring".to_string(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: 0,
        request_id: "relay-request-1".to_string(),
        signed_at,
        user_signed_at: signed_at.saturating_sub(1),
        relayer_node_key: "accused".to_string(),
        origin_protocol: "pre".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 2,
        actor_id: "did:key:z6Mkactor".to_string(),
        object_id: "relay-object".to_string(),
        valid_window_start: Some(signed_at.saturating_sub(10)),
        valid_window_end: Some(signed_at + 10),
        timestamp: Some(signed_at),
        document_inline: false,
    }
}

fn relay_request_envelope(ring: &RingPayload, statement: &RelayRequestStatement) -> ReportEnvelope {
    ReportEnvelope {
        domain: REPORT_DOMAIN.to_string(),
        report_type: UNAUTHORIZED_REQUEST_REPORT_TYPE.to_string(),
        chain_id: statement.chain_id.clone(),
        ring_id: statement.ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        reporter_node_key: "reporter".to_string(),
        accused_node_key: statement.relayer_node_key.clone(),
        accused_peer_id: "aa".repeat(32),
        observed_at: statement.signed_at - CHAIN_BLOCK_GRACE_SECS,
        expires_at: statement.signed_at - CHAIN_BLOCK_GRACE_SECS + REPORT_TTL_SECS,
        payload: Vec::new(),
        session_id: statement.request_id.clone(),
    }
}

fn validation_context(
    app_state: &crate::app_state::AppState<DkgImpl>,
    now: u64,
) -> ReportValidationContext {
    ReportValidationContext {
        local_node_key: app_state.node_key.clone(),
        requester_peer_id: None,
        network: app_state.network.clone(),
        peer_connection_pool: app_state.peer_connection_pool.clone(),
        bulletin: app_state.bulletin.clone(),
        authz: app_state.authz.clone(),
        local_storage: app_state.local_storage.clone(),
        routes: &network::V0,
        now,
        mode: ReportValidationMode::ReporterObservation,
        inline_document: None,
    }
}

fn dkg_share_statement(mutate_share: bool) -> DkgShareStatement {
    let ring = ring_fixture(2);
    let mut dealer = DkgImpl::new(2, 2, 3, 7, DkgRole::Standard).unwrap();
    dealer.generate_polynomial(DkgMode::Fresh).unwrap();
    let commitment = serialize_commitment_coefficients(&dealer.commitment().coefficients).unwrap();
    let share = dealer
        .generate_shares()
        .unwrap()
        .into_iter()
        .find(|share| share.to_id == 1)
        .unwrap();
    let mut share_value = <ScalarField as CryptoSerialize>::to_bytes(&share.value).unwrap();
    if mutate_share {
        let mut bad_share = ScalarField::from_bytes(&share_value).unwrap();
        bad_share += ScalarField::from(1u64);
        share_value = <ScalarField as CryptoSerialize>::to_bytes(&bad_share).unwrap();
    }
    let signed_at = CHAIN_BLOCK_GRACE_SECS + 100;
    let commitment_statement = DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: "chain".to_string(),
        ring_id: "ring".to_string(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&ring),
        protocol_version: 0,
        request_id: "dkg-session-1".to_string(),
        signed_at: signed_at - 1,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 2,
        commitment,
        session_nonce: [0u8; 16],
        attempt_id: [9; 32],
        crypto_backend: DkgImpl::name(),
    };
    DkgShareStatement {
        domain: DKG_SHARE_DOMAIN.to_string(),
        chain_id: "chain".to_string(),
        ring_id: "ring".to_string(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&ring),
        protocol_version: 0,
        request_id: "dkg-session-1".to_string(),
        signed_at,
        responder_node_key: "accused".to_string(),
        receiver_node_key: "reporter".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 2,
        to_node_id: share.to_id,
        commitment_statement,
        commitment_signature: vec![7; 64],
        share_value,
        nonce: share.nonce,
        crypto_backend: DkgImpl::name(),
    }
}

fn dkg_invalid_observation() -> InvalidCryptoResponseObservation {
    let statement = dkg_share_statement(true);
    InvalidCryptoResponseObservation {
        ring_id: "ring".to_string(),
        accused_node_key: "accused".to_string(),
        accused_peer_id: "aa".repeat(32),
        observed_at: statement.signed_at - CHAIN_BLOCK_GRACE_SECS,
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgShare {
            statement: Box::new(statement),
            response_signature: vec![9; 64],
        },
    }
}

#[test]
fn routes_node_offline_observation_to_handler() {
    let registry = ReportRegistry::with_defaults();
    let handler = registry
        .handler_for_observation(&ReportObservation::NodeOffline(offline_observation()))
        .unwrap();
    assert_eq!(handler.report_type(), NODE_OFFLINE_REPORT_TYPE);
}

#[test]
fn routes_pre_invalid_observation_to_handler() {
    let registry = ReportRegistry::with_defaults();
    let handler = registry
        .handler_for_observation(&ReportObservation::InvalidCryptoResponse(Box::new(
            pre_invalid_observation(),
        )))
        .unwrap();
    assert_eq!(handler.report_type(), INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
}

#[test]
fn node_offline_handler_builds_envelope_key_and_signing_options() {
    let ring = ring_fixture(2);
    let observation = offline_observation();
    let handler = NodeOfflineHandler;
    let report_observation = ReportObservation::NodeOffline(observation.clone());

    let key = handler.in_flight_key(&report_observation).unwrap();
    assert_eq!(key.report_type, NODE_OFFLINE_REPORT_TYPE);
    assert_eq!(key.ring_id, "ring");
    assert_eq!(key.subject_key, "accused");

    let built = handler.build_envelope(&observation, &ring, "reporter", "chain".to_string());
    assert_eq!(built, envelope(&ring));
    assert_eq!(built.report_id(), envelope(&ring).report_id());

    let options = handler.signing_options(&built);
    assert!(options.excluded_node_keys.contains("accused"));
    assert!(!options.excluded_node_keys.contains("reporter"));
}

#[test]
fn pre_invalid_handler_builds_envelope_key_and_signing_options() {
    let ring = ring_fixture(2);
    let observation = pre_invalid_observation();
    let handler = InvalidCryptoResponseHandler;
    let report_observation =
        ReportObservation::InvalidCryptoResponse(Box::new(observation.clone()));

    let key = handler.in_flight_key(&report_observation).unwrap();
    assert_eq!(key.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(key.ring_id, "ring");
    assert_eq!(key.subject_key, "accused:pre-request-1");

    let built = handler.build_envelope(&observation, &ring, "reporter", "chain".to_string());
    assert_eq!(built.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(built.session_id, "pre-request-1");
    assert_eq!(built.payload, observation.evidence.canonical_bytes());

    let options = handler.signing_options(&built);
    assert!(options.excluded_node_keys.contains("accused"));
    assert!(!options.excluded_node_keys.contains("reporter"));
}

#[test]
fn dkg_invalid_handler_builds_envelope_from_share_evidence() {
    let ring = ring_fixture(2);
    let observation = dkg_invalid_observation();
    let handler = InvalidCryptoResponseHandler;
    let report_observation =
        ReportObservation::InvalidCryptoResponse(Box::new(observation.clone()));

    let key = handler.in_flight_key(&report_observation).unwrap();
    assert_eq!(key.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(key.ring_id, "ring");
    // DKG evidence kinds fold `attempt_id` into the subject key (unlike
    // PRE/Sign) so two attempts of the same ceremony against the same
    // accused don't collide in-flight — see `in_flight_key`'s own
    // comment. `dkg_share_statement`'s fixture uses `attempt_id: [9; 32]`.
    assert_eq!(
        key.subject_key,
        format!("accused:dkg-session-1:{}", hex::encode([9u8; 32]))
    );

    let built = handler.build_envelope(&observation, &ring, "reporter", "chain".to_string());
    assert_eq!(built.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    assert_eq!(built.session_id, "dkg-session-1");
    assert_eq!(built.payload, observation.evidence.canonical_bytes());
    assert_eq!(built.observed_at, observation.observed_at);

    let options = handler.signing_options(&built);
    assert!(options.excluded_node_keys.contains("accused"));
    assert!(!options.excluded_node_keys.contains("reporter"));
}

#[test]
fn invalid_crypto_in_flight_key_includes_evidence_request_id() {
    let handler = InvalidCryptoResponseHandler;
    let pre = ReportObservation::InvalidCryptoResponse(Box::new(pre_invalid_observation()));
    let sign = ReportObservation::InvalidCryptoResponse(Box::new(sign_invalid_observation()));

    let pre_key = handler.in_flight_key(&pre).unwrap();
    let sign_key = handler.in_flight_key(&sign).unwrap();

    assert_ne!(pre_key, sign_key);
    assert_eq!(pre_key.subject_key, "accused:pre-request-1");
    assert_eq!(sign_key.subject_key, "accused:sign-request-1");
}

#[test]
fn evidence_anchor_requires_exact_backdated_observed_at() {
    let signed_at = 1_700_000_000u64;
    let anchored = signed_at - CHAIN_BLOCK_GRACE_SECS;

    validate_evidence_anchor(signed_at, anchored).unwrap();

    // Any drift decouples the envelope's expires_at from the evidence age,
    // which would let one signed bad response be re-reported after the
    // chain prunes its dedupe records.
    for observed_at in [anchored - 1, anchored + 1, signed_at, 0] {
        assert!(matches!(
            validate_evidence_anchor(signed_at, observed_at),
            Err(ReportingError::Unauthorized(_))
        ));
    }

    // signed_at below the grace can never be anchored.
    assert!(matches!(
        validate_evidence_anchor(CHAIN_BLOCK_GRACE_SECS - 1, 0),
        Err(ReportingError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn relay_request_statement_shape_accepts_valid_and_rejects_malformed() {
    let db_name = "registry_relay_request_statement_shape";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let ring = ring_fixture(2);
    let valid = relay_request_statement(&ring, app_state.bulletin.chain_id(), 110);
    let envelope = relay_request_envelope(&ring, &valid);
    let context = validation_context(&app_state, envelope.observed_at);

    validate_relay_request_statement_shape(&envelope, &context, &valid).unwrap();

    let cases: Vec<(&str, Box<dyn FnOnce(&mut RelayRequestStatement)>)> = vec![
        (
            "wrong origin",
            Box::new(|statement| statement.origin_protocol = "dkg".to_string()),
        ),
        (
            "non-current accused scope",
            Box::new(|statement| statement.accused_committee_scope = CommitteeScope::PendingNew),
        ),
        (
            "non-current signing scope",
            Box::new(|statement| statement.signing_committee_scope = CommitteeScope::PendingNew),
        ),
        (
            "zero from_node_id",
            Box::new(|statement| statement.from_node_id = 0),
        ),
        (
            "empty actor_id",
            Box::new(|statement| statement.actor_id.clear()),
        ),
        (
            "empty object_id",
            Box::new(|statement| statement.object_id.clear()),
        ),
        (
            "half-set valid_window",
            Box::new(|statement| statement.valid_window_end = None),
        ),
        (
            "signed_at/user_signed_at drift",
            Box::new(|statement| {
                statement.user_signed_at = statement.signed_at - RELAY_CHECK_MAX_DRIFT_SECS - 1
            }),
        ),
    ];

    for (case, mutate) in cases {
        let mut statement = valid.clone();
        mutate(&mut statement);
        let error =
            validate_relay_request_statement_shape(&envelope, &context, &statement).unwrap_err();
        assert!(
            matches!(
                error,
                ReportingError::InvalidReport(_) | ReportingError::Unauthorized(_)
            ),
            "{case} should reject as a report validation error, got {error:?}"
        );
    }

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

#[tokio::test]
async fn relayed_request_refutation_rejects_anchor_time_drift() {
    let db_name = "registry_relay_request_anchor_time_drift";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let ring = ring_fixture(2);
    let statement = relay_request_statement(&ring, app_state.bulletin.chain_id(), 1000);
    let context = validation_context(&app_state, statement.signed_at);

    let error = require_relayed_request_unauthorized(&context, &statement, "0")
        .await
        .unwrap_err();

    crate::helpers::test_helpers::cleanup_db(&db_path);
    assert!(error.to_string().contains("anchor time"));
}

#[tokio::test]
async fn relayed_request_refutation_rejects_authorized_request() {
    let db_name = "registry_relay_request_authorized";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let ring = ring_fixture(2);
    let bulletin = std::sync::Arc::new(DummyBulletin::default());

    let document = DocumentPayload {
        ring_id: "ring".to_string(),
        document: "{}".to_string(),
        proof: String::new(),
        policy_id: "policy".to_string(),
        resource: "document".to_string(),
        permission: "read".to_string(),
        tier: Some("tier-a".to_string()),
        timestamp: Some(10),
    };
    bulletin.set_post(
        "relay-pre-object".to_string(),
        BulletinPost {
            id: "relay-pre-object".to_string(),
            payload: document.try_into().unwrap(),
        },
    );

    let key_derivation = KeyDerivation {
        ring_id: "ring".to_string(),
        derivation: "derivation".to_string(),
        policy_id: "policy".to_string(),
        resource: "key".to_string(),
        permission: "sign".to_string(),
    };
    bulletin.set_post(
        "relay-sign-object".to_string(),
        BulletinPost {
            id: "relay-sign-object".to_string(),
            payload: serde_json::to_vec(&key_derivation).unwrap(),
        },
    );

    let base_context = validation_context(&app_state, 10);
    let context = ReportValidationContext {
        bulletin,
        ..base_context
    };

    // DummyAuthZ always authorizes. The positive unauthorized branch belongs in
    // Docker/integration coverage, or a future unit fixture with deny-authz behavior.
    for (origin_protocol, object_id) in [("pre", "relay-pre-object"), ("sign", "relay-sign-object")]
    {
        let mut statement = relay_request_statement(&ring, context.bulletin.chain_id(), 10);
        statement.origin_protocol = origin_protocol.to_string();
        statement.object_id = object_id.to_string();

        let error = require_relayed_request_unauthorized(&context, &statement, "0")
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("relayed request was authorized"),
            "{origin_protocol} should reject authorized requests, got {error}"
        );
    }

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

fn matching_document_evidence() -> ReportedDocumentEvidence {
    ReportedDocumentEvidence {
        document: "{}".to_string(),
        proof: String::new(),
        policy_id: "policy".to_string(),
        resource: "document".to_string(),
        permission: "read".to_string(),
        tier: Some("tier-a".to_string()),
    }
}

/// The out-of-band inline-document evidence (in `ReportValidationContext.inline_document`,
/// never on chain) that hashes to the signed `object_id` reaches the same "authorized"
/// refutation as a bulletin-sourced request — without ever posting the document to the
/// bulletin. Proves the hash recompute is what's gating the check, not a bulletin lookup.
#[tokio::test]
async fn relayed_request_refutation_accepts_matching_inline_document() {
    let db_name = "registry_relay_request_inline_document_matches";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let ring = ring_fixture(2);
    let bulletin = std::sync::Arc::new(DummyBulletin::default());
    let evidence = matching_document_evidence();
    let base_context = validation_context(&app_state, 10);
    let context = ReportValidationContext {
        bulletin,
        inline_document: Some(evidence.clone()),
        ..base_context
    };

    let mut statement = relay_request_statement(&ring, context.bulletin.chain_id(), 10);
    statement.origin_protocol = "pre".to_string();
    statement.timestamp = Some(10);
    statement.object_id = generate_document_id(
        &statement.ring_id,
        &evidence.document,
        &evidence.proof,
        &evidence.policy_id,
        &evidence.resource,
        &evidence.permission,
        evidence.tier.as_deref(),
        statement.timestamp,
    );
    statement.document_inline = true;

    // DummyAuthZ always authorizes, so this must still hit the "authorized" refutation —
    // proving the request reached the real ACP check rather than failing earlier on a
    // (nonexistent) bulletin read.
    let error = require_relayed_request_unauthorized(&context, &statement, "0")
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("relayed request was authorized"),
        "matching inline document evidence should reach the ACP check, got {error}"
    );

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

/// Inline-document evidence whose fields don't hash to `object_id` must be rejected before any
/// ACP/chain work — this is the confused-deputy check for report evidence.
#[tokio::test]
async fn relayed_request_refutation_rejects_mismatched_inline_document() {
    let db_name = "registry_relay_request_inline_document_mismatch";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let ring = ring_fixture(2);
    let bulletin = std::sync::Arc::new(DummyBulletin::default());
    let base_context = validation_context(&app_state, 10);
    let context = ReportValidationContext {
        bulletin,
        inline_document: Some(matching_document_evidence()),
        ..base_context
    };

    let mut statement = relay_request_statement(&ring, context.bulletin.chain_id(), 10);
    statement.origin_protocol = "pre".to_string();
    statement.timestamp = Some(10);
    statement.object_id = "claimed-object-id".to_string();
    statement.document_inline = true;

    let error = require_relayed_request_unauthorized(&context, &statement, "0")
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("does not match object_id"),
        "mismatched inline document evidence should be rejected before the ACP check, got {error}"
    );

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

/// A statement that marks the request inline but reaches a validator with no out-of-band
/// evidence is rejected — there is nothing to re-bind to `object_id` and no bulletin copy.
#[tokio::test]
async fn relayed_request_refutation_rejects_missing_inline_document_evidence() {
    let db_name = "registry_relay_request_inline_document_missing";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let ring = ring_fixture(2);
    let bulletin = std::sync::Arc::new(DummyBulletin::default());
    let base_context = validation_context(&app_state, 10);
    let context = ReportValidationContext {
        bulletin,
        ..base_context
    };

    let mut statement = relay_request_statement(&ring, context.bulletin.chain_id(), 10);
    statement.origin_protocol = "pre".to_string();
    statement.timestamp = Some(10);
    statement.document_inline = true;

    let error = require_relayed_request_unauthorized(&context, &statement, "0")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no inline document evidence was provided"),
        "missing inline document evidence should be rejected, got {error}"
    );

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

/// `require_pre_proof_verification_failure`'s inline-document hash check runs before any
/// crypto (rdr_pk/share/challenge/proof parsing, polynomial lookup) — a mismatch is rejected
/// immediately, so this doesn't need a real proof/local_storage fixture to exercise it.
#[tokio::test]
async fn pre_proof_refutation_rejects_mismatched_inline_document() {
    let db_name = "registry_pre_proof_inline_document_mismatch";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let base_context = validation_context(&app_state, 10);
    let context = ReportValidationContext {
        inline_document: Some(ReportedDocumentEvidence {
            document: "{}".to_string(),
            proof: String::new(),
            policy_id: "policy".to_string(),
            resource: "document".to_string(),
            permission: "read".to_string(),
            tier: None,
        }),
        ..base_context
    };

    let statement = PreReencryptResponseStatement {
        domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
        chain_id: "chain".to_string(),
        ring_id: "ring".to_string(),
        ring_pk: "ring-pk".to_string(),
        ring_state_sha256: "00".repeat(32),
        protocol_version: 0,
        request_id: "pre-request-1".to_string(),
        signed_at: 10,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pre".to_string(),
        object_id: "claimed-object-id".to_string(),
        rdr_pk: vec![1],
        derivation: None,
        from_node_id: 2,
        share: vec![2],
        challenge: vec![3],
        proof: vec![4],
        crypto_backend: "elgamal/test".to_string(),
        timestamp: Some(10),
        document_inline: true,
    };

    let error = require_pre_proof_verification_failure(&statement, &context)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("does not match object_id"),
        "mismatched inline document evidence should be rejected before any crypto work, got {error}"
    );

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

/// The mirror of the mismatch case: inline evidence that *does* hash to `object_id` passes
/// the hash gate, and its `document` is what `deserialize_secret` parses — so the refutation
/// proceeds into the crypto stage (and there fails on this fixture's deliberately-bogus
/// `rdr_pk`, not on the inline-document check). A full polynomial/proof fixture would be
/// needed to reach a verdict; that path is covered by
/// `pre/v0/coordinator/verification.rs`.
#[tokio::test]
async fn pre_proof_refutation_accepts_matching_inline_document() {
    let db_name = "registry_pre_proof_inline_document_matches";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let base_context = validation_context(&app_state, 10);

    let evidence = ReportedDocumentEvidence {
        // A well-formed `Secret` JSON so `deserialize_secret` succeeds and execution reaches
        // the crypto-input decode below.
        document: r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#
            .to_string(),
        proof: String::new(),
        policy_id: "policy".to_string(),
        resource: "document".to_string(),
        permission: "read".to_string(),
        tier: None,
    };
    let context = ReportValidationContext {
        inline_document: Some(evidence.clone()),
        ..base_context
    };

    let timestamp = Some(10);
    let object_id = generate_document_id(
        "ring",
        &evidence.document,
        &evidence.proof,
        &evidence.policy_id,
        &evidence.resource,
        &evidence.permission,
        evidence.tier.as_deref(),
        timestamp,
    );

    let statement = PreReencryptResponseStatement {
        domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
        chain_id: "chain".to_string(),
        ring_id: "ring".to_string(),
        ring_pk: "ring-pk".to_string(),
        ring_state_sha256: "00".repeat(32),
        protocol_version: 0,
        request_id: "pre-request-1".to_string(),
        signed_at: 10,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pre".to_string(),
        object_id,
        // Bogus on purpose: the refutation reaches the crypto-input decode and fails here,
        // proving it got past the inline-document hash gate and `deserialize_secret`.
        rdr_pk: vec![1],
        derivation: None,
        from_node_id: 2,
        share: vec![2],
        challenge: vec![3],
        proof: vec![4],
        crypto_backend: "elgamal/test".to_string(),
        timestamp,
        document_inline: true,
    };

    let error = require_pre_proof_verification_failure(&statement, &context)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        !error.contains("does not match object_id")
            && !error.contains("no inline document evidence was provided"),
        "matching inline document evidence should pass the hash gate, got {error}"
    );
    assert!(
        error.contains("reader public key"),
        "refutation should reach the crypto-input stage, got {error}"
    );

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

#[test]
fn dkg_share_crypto_failure_is_required() {
    let bad = dkg_share_statement(true);
    require_dkg_share_verification_failure(&bad).unwrap();

    let good = dkg_share_statement(false);
    let error = require_dkg_share_verification_failure(&good).unwrap_err();
    assert!(error
        .to_string()
        .contains("reported DKG share verifies successfully"));
}

#[test]
fn public_origin_policy_is_pss_phase_and_role_scoped() {
    assert!(!public_origin_protocol_allows_phase(
        "pss_refresh",
        DkgPublicPhase::CommitmentHashes,
    ));
    assert!(public_origin_protocol_allows_phase(
        "pss_refresh",
        DkgPublicPhase::CommitmentAudit,
    ));
    assert!(public_origin_role_allowed(
        "pss_refresh",
        ParticipantRef::current(1),
        DkgPublicPhase::RefreshHealthCheck,
    ));
    assert!(!public_origin_role_allowed(
        "pss_refresh",
        ParticipantRef::current(2),
        DkgPublicPhase::RefreshHealthCheck,
    ));
    assert!(public_origin_role_allowed(
        "pss_reshare",
        ParticipantRef::next(1),
        DkgPublicPhase::ReshareParticipantSet,
    ));
    assert!(!public_origin_role_allowed(
        "pss_reshare",
        ParticipantRef::current(1),
        DkgPublicPhase::ReshareParticipantSet,
    ));
}

#[test]
fn dkg_share_undecodable_responder_output_is_treated_as_failure() {
    // A signed but undeserializable share value is attributable bad crypto, so
    // co-signers must accept the report (Ok) rather than refuse it.
    let mut bad_share_value = dkg_share_statement(false);
    bad_share_value.share_value = vec![0xff; 4];
    require_dkg_share_verification_failure(&bad_share_value).unwrap();

    // Likewise for an undeserializable nested commitment.
    let mut bad_commitment = dkg_share_statement(false);
    bad_commitment.commitment_statement.commitment = vec![0xff; 3];
    require_dkg_share_verification_failure(&bad_commitment).unwrap();
}

#[tokio::test]
async fn dkg_share_shape_rejects_wrong_origin() {
    let db_name = "registry_dkg_share_shape_rejects_wrong_origin";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let chain_id = app_state.bulletin.chain_id();
    let ring = ring_fixture(2);
    let mut envelope = InvalidCryptoResponseHandler.build_envelope(
        &dkg_invalid_observation(),
        &ring,
        "reporter",
        chain_id.clone(),
    );
    let mut statement = dkg_share_statement(true);
    statement.chain_id = chain_id.clone();
    statement.commitment_statement.chain_id = chain_id;
    statement.origin_protocol = "fresh_dkg".to_string();
    statement.commitment_statement.origin_protocol = "fresh_dkg".to_string();
    envelope.payload = InvalidCryptoResponse::DkgShare {
        statement: Box::new(statement.clone()),
        response_signature: vec![9; 64],
    }
    .canonical_bytes();

    let error = validate_dkg_share_statement_shape(
        &envelope,
        &statement,
        &[9; 64],
        &ReportValidationContext {
            local_node_key: app_state.node_key.clone(),
            requester_peer_id: None,
            network: app_state.network.clone(),
            peer_connection_pool: app_state.peer_connection_pool.clone(),
            bulletin: app_state.bulletin.clone(),
            authz: app_state.authz.clone(),
            local_storage: app_state.local_storage.clone(),
            routes: &network::V0,
            now: envelope.observed_at,
            mode: ReportValidationMode::ReporterObservation,
            inline_document: None,
        },
    )
    .unwrap_err();
    crate::helpers::test_helpers::cleanup_db(&db_path);
    assert!(error.to_string().contains("unsupported DKG share origin"));
}

fn equivocation_commitment(
    ring: &RingPayload,
    chain_id: &str,
    commitment: Vec<u8>,
    session_nonce: [u8; 16],
    signed_at: u64,
) -> SignedDkgCommitment {
    SignedDkgCommitment {
        statement: DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: chain_id.to_string(),
            ring_id: "ring".to_string(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            protocol_version: 0,
            request_id: "dkg-session-1".to_string(),
            signed_at,
            responder_node_key: "accused".to_string(),
            origin_protocol: "pss_reshare".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            commitment,
            session_nonce,
            attempt_id: [9; 32],
            crypto_backend: DkgImpl::name(),
        },
        signature: vec![1; 64],
    }
}

#[tokio::test]
async fn validate_equivocation_commitment_shape_accepts_bound_and_rejects_bad_origin() {
    let db_name = "registry_equivocation_commitment_shape";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let chain_id = app_state.bulletin.chain_id();
    let ring = ring_fixture(2);

    let mut dealer = DkgImpl::new(2, 2, 3, 7, DkgRole::Standard).unwrap();
    dealer.generate_polynomial(DkgMode::Fresh).unwrap();
    let commitment = serialize_commitment_coefficients(&dealer.commitment().coefficients).unwrap();
    let signed_at = CHAIN_BLOCK_GRACE_SECS + 100;
    let nonce = [3u8; 16];
    let commitment_a =
        equivocation_commitment(&ring, &chain_id, commitment.clone(), nonce, signed_at);
    let mut different = commitment.clone();
    different[0] ^= 0xff;
    let commitment_b = equivocation_commitment(&ring, &chain_id, different, nonce, signed_at);

    let observation = InvalidCryptoResponseObservation {
        ring_id: "ring".to_string(),
        accused_node_key: "accused".to_string(),
        accused_peer_id: "aa".repeat(32),
        observed_at: signed_at - CHAIN_BLOCK_GRACE_SECS,
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgEquivocation {
            commitment_a: Box::new(commitment_a.clone()),
            commitment_b: Box::new(commitment_b),
        },
    };
    let envelope = InvalidCryptoResponseHandler.build_envelope(
        &observation,
        &ring,
        "reporter",
        chain_id.clone(),
    );
    let context = ReportValidationContext {
        local_node_key: app_state.node_key.clone(),
        requester_peer_id: None,
        network: app_state.network.clone(),
        peer_connection_pool: app_state.peer_connection_pool.clone(),
        bulletin: app_state.bulletin.clone(),
        authz: app_state.authz.clone(),
        local_storage: app_state.local_storage.clone(),
        routes: &network::V0,
        now: envelope.observed_at,
        mode: ReportValidationMode::ReporterObservation,
        inline_document: None,
    };

    // A well-bound commitment passes the shape check.
    validate_equivocation_commitment_shape(
        &envelope,
        &context,
        &commitment_a.statement,
        &commitment_a.signature,
        true,
    )
    .unwrap();

    // A non-DKG origin is rejected.
    let mut bad = commitment_a.clone();
    bad.statement.origin_protocol = "not_dkg".to_string();
    let error = validate_equivocation_commitment_shape(
        &envelope,
        &context,
        &bad.statement,
        &bad.signature,
        true,
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported DKG equivocation origin"));

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

fn refresh_commitment(
    ring: &RingPayload,
    chain_id: &str,
    commitment: Vec<u8>,
    signed_at: u64,
) -> SignedDkgCommitment {
    SignedDkgCommitment {
        statement: DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: chain_id.to_string(),
            ring_id: "ring".to_string(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            protocol_version: 0,
            request_id: "refresh-session-1".to_string(),
            signed_at,
            responder_node_key: "accused".to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            commitment,
            session_nonce: [5u8; 16],
            attempt_id: [9; 32],
            crypto_backend: DkgImpl::name(),
        },
        signature: vec![1; 64],
    }
}

#[tokio::test]
async fn validate_refresh_commitment_shape_accepts_and_rejects_wrong_origin() {
    let db_name = "registry_refresh_commitment_shape";
    let db_path = crate::helpers::test_helpers::test_db_path(db_name);
    crate::helpers::test_helpers::cleanup_db(&db_path);
    let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
    let chain_id = app_state.bulletin.chain_id();
    let ring = ring_fixture(2);

    // The shape validator only checks structure (not the refutation), so any real
    // commitment shape works here.
    let mut dealer = DkgImpl::new(2, 2, 3, 7, DkgRole::Standard).unwrap();
    dealer.generate_polynomial(DkgMode::Fresh).unwrap();
    let commitment = serialize_commitment_coefficients(&dealer.commitment().coefficients).unwrap();
    let signed_at = CHAIN_BLOCK_GRACE_SECS + 100;
    let commitment = refresh_commitment(&ring, &chain_id, commitment, signed_at);

    let observation = InvalidCryptoResponseObservation {
        ring_id: "ring".to_string(),
        accused_node_key: "accused".to_string(),
        accused_peer_id: "aa".repeat(32),
        observed_at: signed_at - CHAIN_BLOCK_GRACE_SECS,
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgInvalidRefreshCommitment {
            statement: Box::new(commitment.statement.clone()),
            response_signature: commitment.signature.clone(),
        },
    };
    let envelope = InvalidCryptoResponseHandler.build_envelope(
        &observation,
        &ring,
        "reporter",
        chain_id.clone(),
    );
    let context = ReportValidationContext {
        local_node_key: app_state.node_key.clone(),
        requester_peer_id: None,
        network: app_state.network.clone(),
        peer_connection_pool: app_state.peer_connection_pool.clone(),
        bulletin: app_state.bulletin.clone(),
        authz: app_state.authz.clone(),
        local_storage: app_state.local_storage.clone(),
        routes: &network::V0,
        now: envelope.observed_at,
        mode: ReportValidationMode::ReporterObservation,
        inline_document: None,
    };

    // A well-formed pss_refresh commitment passes the shape check.
    validate_refresh_commitment_statement_shape(
        &envelope,
        &commitment.statement,
        &commitment.signature,
        &context,
    )
    .unwrap();

    // A reshare origin is rejected: reshare commitments legitimately have a
    // non-identity constant term, so they must never be reportable as invalid refresh.
    let mut bad = commitment.clone();
    bad.statement.origin_protocol = "pss_reshare".to_string();
    let error = validate_refresh_commitment_statement_shape(
        &envelope,
        &bad.statement,
        &bad.signature,
        &context,
    )
    .unwrap_err();
    assert!(error.to_string().contains("requires pss_refresh origin"));

    crate::helpers::test_helpers::cleanup_db(&db_path);
}

#[test]
fn require_refresh_commitment_is_invalid_rejects_identity_and_accepts_non_identity() {
    let ring = ring_fixture(2);
    let chain_id = "test-chain";

    // Refresh mode → identity constant term → a VALID refresh commitment → report rejected.
    let mut refresh_dealer = DkgImpl::new(2, 2, 3, 7, DkgRole::Standard).unwrap();
    refresh_dealer
        .generate_polynomial(DkgMode::Refresh)
        .unwrap();
    let identity_commitment =
        serialize_commitment_coefficients(&refresh_dealer.commitment().coefficients).unwrap();
    let valid = refresh_commitment(&ring, chain_id, identity_commitment, 100);
    let error = require_refresh_commitment_is_invalid(&valid.statement).unwrap_err();
    assert!(error.to_string().contains("identity constant term"));

    // Fresh mode → non-identity constant term → the dealer tried to shift the ring key
    // → report stands.
    let mut fresh_dealer = DkgImpl::new(2, 2, 3, 7, DkgRole::Standard).unwrap();
    fresh_dealer.generate_polynomial(DkgMode::Fresh).unwrap();
    let non_identity_commitment =
        serialize_commitment_coefficients(&fresh_dealer.commitment().coefficients).unwrap();
    let invalid = refresh_commitment(&ring, chain_id, non_identity_commitment, 100);
    require_refresh_commitment_is_invalid(&invalid.statement).unwrap();

    // An undecodable commitment is itself an attributable fault → report stands.
    let mut undecodable = valid.clone();
    undecodable.statement.commitment = vec![0xff; 3];
    require_refresh_commitment_is_invalid(&undecodable.statement).unwrap();
}

#[test]
fn report_protocol_version_is_resolved_at_observed_at() {
    let mut ring = ring_fixture(2);
    ring.upgrade_info = UpgradeInfo {
        current_version: 0,
        next_version: Some(1),
        activation_time: Some(110),
    };
    let mut report = envelope(&ring);
    report.observed_at = 100;

    assert_eq!(
        validate_report_route_version_at_observed_at(&report, &ring, 0).unwrap(),
        0
    );
    assert!(matches!(
        validate_report_route_version_at_observed_at(&report, &ring, 1),
        Err(ReportingError::Unauthorized(_))
    ));

    report.observed_at = 110;
    assert_eq!(
        validate_report_route_version_at_observed_at(&report, &ring, 1).unwrap(),
        1
    );
}

#[test]
fn rejects_threshold_one() {
    let ring = ring_fixture(1);
    let report = envelope(&ring);
    let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
    assert!(error.to_string().contains("threshold >= 2"));
}

#[test]
fn rejects_threshold_that_needs_accused() {
    let ring = ring_fixture(3);
    let report = envelope(&ring);
    let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
    assert!(error.to_string().contains("excluding the accused"));
}

#[test]
fn accepts_current_scope_during_pending_reshare_and_rejects_stale_digest() {
    let mut ring = ring_fixture(2);
    let report = envelope(&ring);
    ring.new_threshold = Some(3);
    ring.new_peer_node_keys = Some(vec![
        "reporter".to_string(),
        "accused".to_string(),
        "validator".to_string(),
    ]);
    let mut scoped_report = report.clone();
    scoped_report.ring_state_sha256 = ring_state_sha256(&ring);
    validate_ring_and_membership(&scoped_report, &payload(&scoped_report), &ring).unwrap();

    let ring = ring_fixture(2);
    let mut report = envelope(&ring);
    report.ring_state_sha256 = "00".repeat(32);
    assert!(validate_ring_and_membership(&report, &payload(&report), &ring).is_err());
}

#[test]
fn accepts_valid_report_shape_against_ring() {
    let ring = ring_fixture(2);
    let report = envelope(&ring);
    validate_ring_and_membership(&report, &payload(&report), &ring).unwrap();
}

#[test]
fn validates_pending_new_accused_and_current_signing_scope() {
    let mut ring = ring_fixture(2);
    ring.new_peer_node_keys = Some(vec![
        "new-a".to_string(),
        "pending-accused".to_string(),
        "new-c".to_string(),
    ]);
    ring.new_threshold = Some(3);

    let mut report = envelope(&ring);
    report.ring_state_sha256 = ring_state_sha256(&ring);
    report.accused_node_key = "pending-accused".to_string();
    report.payload = NodeOffline {
        origin_protocol: "pss_reshare".to_string(),
        origin_protocol_version: 0,
        accused_committee_scope: CommitteeScope::PendingNew,
        signing_committee_scope: CommitteeScope::Current,
    }
    .canonical_bytes();

    validate_ring_and_membership(&report, &payload(&report), &ring).unwrap();
}

#[test]
fn rejects_reporter_outside_signing_committee() {
    let mut ring = ring_fixture(2);
    ring.new_peer_node_keys = Some(vec![
        "new-a".to_string(),
        "pending-accused".to_string(),
        "new-c".to_string(),
    ]);
    ring.new_threshold = Some(2);

    let mut report = envelope(&ring);
    report.ring_state_sha256 = ring_state_sha256(&ring);
    report.payload = NodeOffline {
        origin_protocol: "pss_reshare".to_string(),
        origin_protocol_version: 0,
        accused_committee_scope: CommitteeScope::PendingNew,
        signing_committee_scope: CommitteeScope::PendingNew,
    }
    .canonical_bytes();

    let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
    assert!(error.to_string().contains("signing committee"));
}

#[test]
fn excludes_accused_only_when_in_signing_committee_capacity_check() {
    let mut ring = ring_fixture(3);
    ring.new_peer_node_keys = Some(vec![
        "new-a".to_string(),
        "pending-accused".to_string(),
        "new-c".to_string(),
    ]);
    ring.new_threshold = Some(3);

    let mut report = envelope(&ring);
    report.ring_state_sha256 = ring_state_sha256(&ring);
    report.accused_node_key = "pending-accused".to_string();
    report.payload = NodeOffline {
        origin_protocol: "pss_reshare".to_string(),
        origin_protocol_version: 0,
        accused_committee_scope: CommitteeScope::PendingNew,
        signing_committee_scope: CommitteeScope::Current,
    }
    .canonical_bytes();
    validate_ring_and_membership(&report, &payload(&report), &ring).unwrap();

    report.reporter_node_key = "new-a".to_string();
    report.payload = NodeOffline {
        origin_protocol: "pss_reshare".to_string(),
        origin_protocol_version: 0,
        accused_committee_scope: CommitteeScope::PendingNew,
        signing_committee_scope: CommitteeScope::PendingNew,
    }
    .canonical_bytes();
    let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
    assert!(error.to_string().contains("excluding the accused"));
}

#[test]
fn rejects_unknown_report_type() {
    let registry = ReportRegistry::with_defaults();
    assert!(matches!(
        registry.handler_for("future_fault"),
        Err(ReportingError::UnsupportedReportType { .. })
    ));
}

#[test]
fn accused_not_in_accused_committee_is_rejected() {
    let ring = ring_fixture(2);
    let mut report = envelope(&ring);
    report.accused_node_key = "outsider".to_string();
    let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
    assert!(error.to_string().contains("accused committee"));
}

#[test]
fn expected_leader_manifest_shape_rejects_reshare_commitments() {
    // The one deliberately-unsupported phase: expected origins there
    // depend on live active-dealer selection, not chain-derivable
    // committee membership — see `expected_leader_manifest_shape`'s doc
    // comment.
    let ring = ring_fixture(2);
    let error = expected_leader_manifest_shape(&ring, "pss_reshare", DkgPublicPhase::Commitments)
        .unwrap_err();
    assert!(error.to_string().contains("not supported"));
}

#[test]
fn expected_leader_manifest_shape_refresh_commitments_is_the_whole_current_committee() {
    let ring = ring_fixture(2);
    let shape =
        expected_leader_manifest_shape(&ring, "pss_refresh", DkgPublicPhase::Commitments).unwrap();
    assert!(shape.complete);
    let expected: BTreeSet<ParticipantRef> =
        committee_participant_refs(&ring.peer_node_keys, transport::CommitteeScope::Current)
            .unwrap();
    assert_eq!(shape.origins, expected);
    assert_eq!(shape.origins.len(), ring.peer_node_keys.len());
}

#[test]
fn expected_leader_manifest_shape_refresh_health_check_is_leader_only() {
    let ring = ring_fixture(2);
    let shape =
        expected_leader_manifest_shape(&ring, "pss_refresh", DkgPublicPhase::RefreshHealthCheck)
            .unwrap();
    assert!(shape.complete);
    assert_eq!(shape.origins, BTreeSet::from([ParticipantRef::current(1)]));
}

#[test]
fn expected_leader_manifest_shape_reshare_commitment_audit_requires_pending_reshare() {
    let mut ring = ring_fixture(2);
    ring.new_peer_node_keys = None;
    let error =
        expected_leader_manifest_shape(&ring, "pss_reshare", DkgPublicPhase::CommitmentAudit)
            .unwrap_err();
    assert!(error.to_string().contains("pending reshare"));

    ring.new_peer_node_keys = Some(vec!["accused".to_string(), "newcomer".to_string()]);
    let shape =
        expected_leader_manifest_shape(&ring, "pss_reshare", DkgPublicPhase::CommitmentAudit)
            .unwrap();
    assert!(!shape.complete);
    let expected: BTreeSet<ParticipantRef> = committee_participant_refs(
        ring.new_peer_node_keys.as_deref().unwrap(),
        transport::CommitteeScope::Next,
    )
    .unwrap();
    assert_eq!(shape.origins, expected);
}

#[test]
fn expected_leader_manifest_shape_reshare_participant_set_is_leader_only() {
    let mut ring = ring_fixture(2);
    ring.new_peer_node_keys = Some(vec!["accused".to_string(), "newcomer".to_string()]);
    let shape =
        expected_leader_manifest_shape(&ring, "pss_reshare", DkgPublicPhase::ReshareParticipantSet)
            .unwrap();
    assert!(shape.complete);
    assert_eq!(shape.origins, BTreeSet::from([ParticipantRef::next(1)]));
}

#[test]
fn expected_leader_manifest_shape_rejects_unsupported_phase_for_origin_protocol() {
    let ring = ring_fixture(2);
    let error =
        expected_leader_manifest_shape(&ring, "pss_refresh", DkgPublicPhase::ReshareParticipantSet)
            .unwrap_err();
    assert!(error.to_string().contains("not valid for origin protocol"));
}
