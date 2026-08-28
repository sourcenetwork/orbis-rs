use super::*;
use bulletin::r#trait::UpgradeInfo;

fn envelope() -> ReportEnvelope {
    ReportEnvelope {
        domain: REPORT_DOMAIN.to_string(),
        report_type: NODE_OFFLINE_REPORT_TYPE.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        reporter_node_key: "reporter".to_string(),
        accused_node_key: "accused".to_string(),
        accused_peer_id: "22".repeat(32),
        observed_at: 1_700_000_000,
        expires_at: 1_700_000_120,
        payload: NodeOffline {
            origin_protocol: "pre".to_string(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
        }
        .canonical_bytes(),
        session_id: "pre-request-1".to_string(),
    }
}

fn relay_request_statement() -> RelayRequestStatement {
    RelayRequestStatement {
        domain: RELAY_REQUEST_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 0,
        request_id: "sign-request-1".to_string(),
        signed_at: 1_700_000_000,
        user_signed_at: 1_699_999_995,
        relayer_node_key: "relayer".to_string(),
        origin_protocol: "sign".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 2,
        actor_id: "did:key:z6Mkactor".to_string(),
        object_id: "derivation-1".to_string(),
        valid_window_start: Some(1_699_999_000),
        valid_window_end: Some(1_700_001_000),
        timestamp: Some(1_700_000_000),
        document_inline: false,
    }
}

#[test]
fn relay_request_statement_round_trips() {
    let statement = relay_request_statement();
    assert_eq!(
        RelayRequestStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
        statement
    );
}

#[test]
fn relay_request_statement_with_document_inline_round_trips() {
    let mut statement = relay_request_statement();
    statement.document_inline = true;
    assert_eq!(
        RelayRequestStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
        statement
    );
    // The inline document's ciphertext never reaches the wire: flipping the marker only
    // changes the one bool byte, never appends evidence.
    assert_eq!(
        statement.canonical_bytes().len(),
        relay_request_statement().canonical_bytes().len()
    );
}

#[test]
fn unauthorized_request_payload_round_trips() {
    let payload = UnauthorizedRequestPayload {
        statement: relay_request_statement(),
        relay_signature: vec![7; 64],
        checked_at_anchor: "42000".to_string(),
    };
    assert_eq!(
        UnauthorizedRequestPayload::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
        payload
    );
    // A statement with no window/timestamp (unbounded auth) also round-trips.
    let mut unbounded = payload.clone();
    unbounded.statement.valid_window_start = None;
    unbounded.statement.valid_window_end = None;
    unbounded.statement.timestamp = None;
    assert_eq!(
        UnauthorizedRequestPayload::from_canonical_bytes(&unbounded.canonical_bytes()).unwrap(),
        unbounded
    );
}

#[test]
fn offline_payload_round_trips() {
    let payload = NodeOffline {
        origin_protocol: "pre".to_string(),
        origin_protocol_version: 7,
        accused_committee_scope: CommitteeScope::PendingNew,
        signing_committee_scope: CommitteeScope::Current,
    };
    assert_eq!(
        NodeOffline::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
        payload
    );
}

fn pre_statement() -> PreReencryptResponseStatement {
    PreReencryptResponseStatement {
        domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "pre-request-1".to_string(),
        signed_at: 1_700_000_000 + CHAIN_BLOCK_GRACE_SECS,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pre".to_string(),
        object_id: "object-1".to_string(),
        rdr_pk: vec![1, 2, 3],
        derivation: Some(vec![4, 5, 6]),
        from_node_id: 2,
        share: vec![7, 8],
        challenge: vec![9, 10],
        proof: vec![11, 12],
        crypto_backend: "elgamal/test".to_string(),
        timestamp: Some(1_700_000_000),
        document_inline: false,
    }
}

fn dkg_commitment_statement() -> DkgCommitmentStatement {
    DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "dkg-session-1".to_string(),
        signed_at: 1_700_000_000,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 2,
        commitment: vec![1, 2, 3],
        session_nonce: [0u8; 16],
        attempt_id: [9; 32],
        crypto_backend: "dkg/test".to_string(),
    }
}

fn dkg_share_statement() -> DkgShareStatement {
    DkgShareStatement {
        domain: DKG_SHARE_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "dkg-session-1".to_string(),
        signed_at: 1_700_000_000 + CHAIN_BLOCK_GRACE_SECS,
        responder_node_key: "accused".to_string(),
        receiver_node_key: "receiver".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: 2,
        to_node_id: 1,
        commitment_statement: dkg_commitment_statement(),
        commitment_signature: vec![41; 64],
        share_value: vec![7, 8],
        nonce: [9; 16],
        crypto_backend: "dkg/test".to_string(),
    }
}

#[test]
fn pre_response_statement_round_trips_and_is_domain_separated() {
    let statement = pre_statement();
    assert_eq!(
        PreReencryptResponseStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
        statement
    );

    let mut changed = pre_statement();
    changed.domain = "other".to_string();
    assert_ne!(pre_statement().canonical_bytes(), changed.canonical_bytes());
}

#[test]
fn pre_response_statement_with_document_inline_round_trips() {
    let mut statement = pre_statement();
    statement.document_inline = true;
    assert_eq!(
        PreReencryptResponseStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
        statement
    );
    // The inline document's ciphertext never reaches the wire.
    assert_eq!(
        statement.canonical_bytes().len(),
        pre_statement().canonical_bytes().len()
    );
}

#[test]
fn invalid_crypto_response_pre_payload_round_trips() {
    let payload = InvalidCryptoResponse::Pre {
        statement: pre_statement(),
        response_signature: vec![42; 64],
    };

    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
        payload
    );
}

#[test]
fn invalid_crypto_response_sign_payload_round_trips() {
    let payload = InvalidCryptoResponse::Sign {
        statement: SignResponseStatement {
            domain: SIGN_RESPONSE_DOMAIN.to_string(),
            chain_id: "vera-test".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "aabb".to_string(),
            ring_state_sha256: "11".repeat(32),
            protocol_version: 7,
            request_id: "sign-request-1".to_string(),
            signed_at: 1_700_000_000 + CHAIN_BLOCK_GRACE_SECS,
            responder_node_key: "accused".to_string(),
            origin_protocol: "sign".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            message: vec![1, 2, 3],
            signing_commitments: vec![4, 5],
            derivation: None,
            metadata: Some(vec![6, 7]),
            sig_share: vec![8, 9],
            crypto_backend: "threshold-bls-g2".to_string(),
        },
        response_signature: vec![42; 64],
    };

    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
        payload
    );
}

#[test]
fn dkg_share_statement_round_trips_and_binds_nested_commitment() {
    let statement = dkg_share_statement();
    assert_eq!(
        DkgShareStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
        statement
    );

    let mut changed = dkg_share_statement();
    changed.commitment_statement.commitment.push(99);
    assert_ne!(
        dkg_share_statement().canonical_bytes(),
        changed.canonical_bytes()
    );
}

#[test]
fn dkg_commitment_statement_round_trips_and_binds_session_nonce() {
    let statement = dkg_commitment_statement();
    assert_eq!(
        DkgCommitmentStatement::from_canonical_bytes(&statement.canonical_bytes()).unwrap(),
        statement
    );

    // The per-attempt nonce is part of the signed bytes — changing it changes them.
    let mut changed = dkg_commitment_statement();
    changed.session_nonce = [7u8; 16];
    assert_ne!(
        dkg_commitment_statement().canonical_bytes(),
        changed.canonical_bytes()
    );

    // attempt_id must be bound into the signed bytes too, not just
    // carried alongside them — that's what makes it tamper-proof enough to
    // fold into the chain-side sessionDedupeID (see reporting/README.md's
    // "Two distinct dedupe keys" section). Unlike session_nonce (self-chosen
    // by the dealer, only usable for equivocation-nonce matching), attempt_id
    // is network-assigned, so this binding is what lets it double as a safe
    // dedupe-scoping key.
    let mut changed_attempt = dkg_commitment_statement();
    changed_attempt.attempt_id = [7u8; 32];
    assert_ne!(
        dkg_commitment_statement().canonical_bytes(),
        changed_attempt.canonical_bytes()
    );
}

#[test]
fn invalid_crypto_response_dkg_share_payload_round_trips() {
    let payload = InvalidCryptoResponse::DkgShare {
        statement: Box::new(dkg_share_statement()),
        response_signature: vec![42; 64],
    };

    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
        payload
    );
    assert_eq!(payload.signing_committee_scope(), CommitteeScope::Current);
}

#[test]
fn invalid_crypto_response_dkg_invalid_refresh_commitment_payload_round_trips() {
    let mut statement = dkg_commitment_statement();
    statement.origin_protocol = "pss_refresh".to_string();
    let payload = InvalidCryptoResponse::DkgInvalidRefreshCommitment {
        statement: Box::new(statement.clone()),
        response_signature: vec![42; 64],
    };

    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
        payload
    );
    assert_eq!(payload.request_id(), statement.request_id);
    assert_eq!(payload.signing_committee_scope(), CommitteeScope::Current);
}

#[test]
fn invalid_crypto_response_dkg_equivocation_payload_round_trips() {
    let mut statement_a = dkg_commitment_statement();
    statement_a.session_nonce = [3u8; 16];
    let mut statement_b = statement_a.clone();
    statement_b.commitment = vec![9, 9, 9]; // conflicting bytes, same nonce
    let payload = InvalidCryptoResponse::DkgEquivocation {
        commitment_a: Box::new(SignedDkgCommitment {
            statement: statement_a.clone(),
            signature: vec![1; 64],
        }),
        commitment_b: Box::new(SignedDkgCommitment {
            statement: statement_b,
            signature: vec![2; 64],
        }),
    };

    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&payload.canonical_bytes()).unwrap(),
        payload
    );
    assert_eq!(payload.request_id(), statement_a.request_id);
    assert_eq!(payload.signing_committee_scope(), CommitteeScope::Current);
}

#[test]
fn invalid_crypto_response_dkg_public_origin_fault_payload_round_trips() {
    let statement = DkgPublicOriginFaultStatement {
        domain: DKG_PUBLIC_ORIGIN_FAULT_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "900".to_string(),
        signed_at: 1_700_000_010,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: [9; 32],
        phase: "commitments".to_string(),
        fault_kind: DkgPublicOriginFaultKind::InvalidPayload,
        contribution_a: EndpointSignedContribution {
            origin: vec![0x22; 32],
            signature: vec![1; 64],
            data: vec![1, 2, 3],
        },
        contribution_b: None,
    };
    let payload = InvalidCryptoResponse::DkgPublicOriginFault {
        statement: Box::new(statement),
    };
    let encoded = payload.canonical_bytes();
    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&encoded).unwrap(),
        payload
    );
    assert_eq!(
        hex::encode(Sha256::digest(&encoded)),
        "fb23d5d30ac684a95151c669fa2257f00351ba11d963d84ab0b621145b223ef5"
    );
}

#[test]
fn invalid_crypto_response_dkg_leader_equivocation_payload_round_trips() {
    let statement = DkgLeaderEquivocationStatement {
        domain: DKG_LEADER_EQUIVOCATION_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "900".to_string(),
        signed_at: 1_700_000_010,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: [9; 32],
        phase: "commitment_audit".to_string(),
        delivery_id_a: [0xaa; 16],
        delivery_a: EndpointSignedContribution {
            origin: vec![0x22; 32],
            signature: vec![1; 64],
            data: vec![1, 2, 3],
        },
        delivery_id_b: [0xbb; 16],
        delivery_b: EndpointSignedContribution {
            origin: vec![0x22; 32],
            signature: vec![2; 64],
            data: vec![4, 5, 6],
        },
    };
    let payload = InvalidCryptoResponse::DkgLeaderEquivocation {
        statement: Box::new(statement),
    };
    let encoded = payload.canonical_bytes();
    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&encoded).unwrap(),
        payload
    );
}

#[test]
fn invalid_crypto_response_dkg_leader_batch_mismatch_payload_round_trips() {
    // Same wire shape as `dkg_leader_equivocation` (this evidence kind
    // reuses `DkgLeaderEquivocationStatement` directly), but a distinct
    // domain and evidence_kind tag, so round-tripping through the outer
    // `InvalidCryptoResponse` wrapper must still land on the right
    // variant rather than being confused with real leader-equivocation
    // evidence.
    let statement = DkgLeaderEquivocationStatement {
        domain: DKG_LEADER_BATCH_MISMATCH_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "900".to_string(),
        signed_at: 1_700_000_010,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: [9; 32],
        phase: "commitment_audit".to_string(),
        delivery_id_a: [0xaa; 16],
        delivery_a: EndpointSignedContribution {
            origin: vec![0x22; 32],
            signature: vec![1; 64],
            data: vec![1, 2, 3],
        },
        delivery_id_b: [0xbb; 16],
        delivery_b: EndpointSignedContribution {
            origin: vec![0x22; 32],
            signature: vec![2; 64],
            data: vec![4, 5, 6],
        },
    };
    let payload = InvalidCryptoResponse::DkgLeaderBatchMismatch {
        statement: Box::new(statement),
    };
    let encoded = payload.canonical_bytes();
    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&encoded).unwrap(),
        payload
    );
}

#[test]
fn invalid_crypto_response_dkg_leader_public_fault_payload_round_trips() {
    let statement = DkgLeaderPublicFaultStatement {
        domain: DKG_LEADER_PUBLIC_FAULT_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "900".to_string(),
        signed_at: 1_700_000_010,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: [9; 32],
        phase: "commitment_audit".to_string(),
        fault_kind: DkgLeaderPublicFaultKind::InvalidManifest,
        delivery_id: [0xaa; 16],
        delivery: EndpointSignedContribution {
            origin: vec![0x22; 32],
            signature: vec![1; 64],
            data: vec![1, 2, 3],
        },
    };
    let payload = InvalidCryptoResponse::DkgLeaderPublicFault {
        statement: Box::new(statement),
    };
    let encoded = payload.canonical_bytes();
    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&encoded).unwrap(),
        payload
    );
}

#[test]
fn dkg_leader_public_fault_statement_round_trips_for_every_fault_kind() {
    for fault_kind in [
        DkgLeaderPublicFaultKind::InvalidManifest,
        DkgLeaderPublicFaultKind::ChunkIndexOutOfRange,
        DkgLeaderPublicFaultKind::OversizedChunk,
        DkgLeaderPublicFaultKind::DuplicateChunkOrigin,
    ] {
        let statement = DkgLeaderPublicFaultStatement {
            domain: DKG_LEADER_PUBLIC_FAULT_DOMAIN.to_string(),
            chain_id: "vera-test".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "aabb".to_string(),
            ring_state_sha256: "11".repeat(32),
            protocol_version: 7,
            request_id: "900".to_string(),
            signed_at: 1_700_000_010,
            responder_node_key: "accused".to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            attempt_id: [9; 32],
            phase: "commitment_audit".to_string(),
            fault_kind,
            delivery_id: [0xaa; 16],
            delivery: EndpointSignedContribution {
                origin: vec![0x22; 32],
                signature: vec![1; 64],
                data: vec![1, 2, 3],
            },
        };
        let encoded = statement.canonical_bytes();
        assert_eq!(
            DkgLeaderPublicFaultStatement::from_canonical_bytes(&encoded).unwrap(),
            statement,
            "fault_kind {fault_kind:?} did not round-trip"
        );
    }
}

#[test]
fn invalid_crypto_response_dkg_control_message_fault_leader_prepare_payload_round_trips() {
    let statement = DkgControlMessageFaultStatement {
        domain: DKG_CONTROL_MESSAGE_FAULT_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "900".to_string(),
        signed_at: 1_700_000_010,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: [9; 32],
        message_kind: "prepare".to_string(),
        fault_kind: DkgControlMessageFaultKind::LeaderPrepareFault,
        artifact_a: ControlMessageArtifact {
            signature: vec![1; 64],
            data: vec![1, 2, 3],
            signed_at: 1_700_000_010,
        },
        artifact_b: None,
    };
    let payload = InvalidCryptoResponse::DkgControlMessageFault {
        statement: Box::new(statement),
    };
    let encoded = payload.canonical_bytes();
    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&encoded).unwrap(),
        payload
    );
}

#[test]
fn invalid_crypto_response_dkg_control_message_fault_ack_equivocation_payload_round_trips() {
    let statement = DkgControlMessageFaultStatement {
        domain: DKG_CONTROL_MESSAGE_FAULT_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "900".to_string(),
        signed_at: 1_700_000_010,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_reshare".to_string(),
        accused_committee_scope: CommitteeScope::PendingNew,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: [9; 32],
        message_kind: "activated".to_string(),
        fault_kind: DkgControlMessageFaultKind::AckEquivocation,
        artifact_a: ControlMessageArtifact {
            signature: vec![2; 64],
            data: vec![0xaa; 32],
            signed_at: 1_700_000_000,
        },
        artifact_b: Some(ControlMessageArtifact {
            signature: vec![3; 64],
            data: vec![0xbb; 32],
            signed_at: 1_700_000_010,
        }),
    };
    let payload = InvalidCryptoResponse::DkgControlMessageFault {
        statement: Box::new(statement),
    };
    let encoded = payload.canonical_bytes();
    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&encoded).unwrap(),
        payload
    );
}

#[test]
fn invalid_crypto_response_dkg_control_message_fault_oversized_repair_page_payload_round_trips() {
    let statement = DkgControlMessageFaultStatement {
        domain: DKG_CONTROL_MESSAGE_FAULT_DOMAIN.to_string(),
        chain_id: "vera-test".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "aabb".to_string(),
        ring_state_sha256: "11".repeat(32),
        protocol_version: 7,
        request_id: "900".to_string(),
        signed_at: 1_700_000_010,
        responder_node_key: "accused".to_string(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: [9; 32],
        message_kind: "public_phase_response".to_string(),
        fault_kind: DkgControlMessageFaultKind::OversizedRepairPage,
        artifact_a: ControlMessageArtifact {
            signature: vec![4; 64],
            data: vec![0xcc; 128],
            signed_at: 1_700_000_010,
        },
        artifact_b: None,
    };
    let payload = InvalidCryptoResponse::DkgControlMessageFault {
        statement: Box::new(statement),
    };
    let encoded = payload.canonical_bytes();
    assert_eq!(
        InvalidCryptoResponse::from_canonical_bytes(&encoded).unwrap(),
        payload
    );
}

#[test]
fn report_id_is_deterministic_and_domain_separated() {
    let report = envelope();
    assert_eq!(report.report_id(), report.report_id());
    let mut changed = report.clone();
    changed.domain = "different-domain".to_string();
    assert_ne!(report.report_id(), changed.report_id());

    let mut changed = report.clone();
    changed.session_id = "pre-request-2".to_string();
    assert_ne!(report.report_id(), changed.report_id());
}

#[test]
fn report_validity_window_is_fixed() {
    let report = envelope();
    report.validate_shape(report.observed_at).unwrap();
    assert!(matches!(
        report.validate_shape(report.expires_at + 1),
        Err(ReportingError::Expired)
    ));
}

#[test]
fn self_reporting_is_rejected() {
    let mut report = envelope();
    report.accused_node_key = report.reporter_node_key.clone();
    assert!(report.validate_shape(report.observed_at).is_err());
}

#[test]
fn report_validity_window_must_be_exactly_ttl() {
    let mut report = envelope();
    report.expires_at = report.observed_at + REPORT_TTL_SECS + 1;
    assert!(report.validate_shape(report.observed_at).is_err());
    let mut report = envelope();
    report.expires_at = report.observed_at + REPORT_TTL_SECS - 1;
    assert!(report.validate_shape(report.observed_at).is_err());
}

#[test]
fn ring_state_digest_commits_to_committee_order() {
    let mut a = RingPayload {
        ring_pk: "pk".into(),
        peer_node_keys: vec!["b".into(), "a".into()],
        threshold: 2,
        pss_interval: 86_400,
        upgrade_info: UpgradeInfo {
            current_version: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut b = a.clone();
    b.peer_node_keys.reverse();
    assert_ne!(ring_state_sha256(&a), ring_state_sha256(&b));
    assert_eq!(
        ring_state_sha256(&a),
        "1dd783721bbfc90f5960d9f2ebd99244c22ab147113d22bd39f9bccf6bf73c39"
    );

    let mut with_empty_relays = b.clone();
    with_empty_relays.trusted_auth_relay_dids = Some(vec![]);
    assert_ne!(ring_state_sha256(&with_empty_relays), ring_state_sha256(&b));

    let mut with_relay = b.clone();
    with_relay.trusted_auth_relay_dids = Some(vec![
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into(),
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".into(),
    ]);
    assert_eq!(
        ring_state_sha256(&with_relay),
        "6d093b9e03af27c7b679341367306e67b64b0afdb5f31ec9e0f5133ebc145ca6"
    );
    assert_ne!(ring_state_sha256(&with_relay), ring_state_sha256(&b));
    with_relay
        .trusted_auth_relay_dids
        .as_mut()
        .expect("relay list")
        .reverse();
    assert_ne!(
        ring_state_sha256(&with_relay),
        "6d093b9e03af27c7b679341367306e67b64b0afdb5f31ec9e0f5133ebc145ca6"
    );

    a.threshold = 1;
    assert_ne!(ring_state_sha256(&a), ring_state_sha256(&b));
}

#[test]
fn report_encoding_golden_vector() {
    assert_eq!(
        envelope().report_id(),
        "954c67cd1885283a0d22a074b0b6db7eb412bad414d4fcfb5ff59cd1719e6dc0"
    );
}
