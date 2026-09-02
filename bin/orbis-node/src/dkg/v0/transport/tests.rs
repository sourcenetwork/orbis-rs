use super::*;

fn committee(entries: &[(&str, &str, u32)], threshold: u32) -> CommitteeConfig {
    CommitteeConfig {
        node_keys: entries
            .iter()
            .map(|(key, _, _)| (*key).to_string())
            .collect(),
        peer_routes: entries
            .iter()
            .map(|(_, route, _)| (*route).to_string())
            .collect(),
        node_id_assignments: entries
            .iter()
            .map(|(key, _, node_id)| ((*key).to_string(), *node_id))
            .collect(),
        threshold,
    }
}

#[test]
fn offline_candidate_ids_are_canonical_and_attempt_bound() {
    let ceremony = CeremonyId(17);
    let attempt = AttemptId([3; 32]);
    let sender = [9; 32];
    let first = derive_offline_candidates_id(
        ceremony,
        attempt,
        &sender,
        PssOfflineStage::Prepare,
        &[ParticipantRef::next(2), ParticipantRef::current(1)],
    )
    .unwrap();
    let reordered = derive_offline_candidates_id(
        ceremony,
        attempt,
        &sender,
        PssOfflineStage::Prepare,
        &[ParticipantRef::current(1), ParticipantRef::next(2)],
    )
    .unwrap();
    let another_attempt = derive_offline_candidates_id(
        ceremony,
        AttemptId([4; 32]),
        &sender,
        PssOfflineStage::Prepare,
        &[ParticipantRef::current(1), ParticipantRef::next(2)],
    )
    .unwrap();
    assert_eq!(first, reordered);
    assert_ne!(first, another_attempt);
    assert!(PssOfflineStage::Prepare.requires_canonical_leader());
    assert!(!PssOfflineStage::PrivatePair.requires_canonical_leader());
}

#[test]
fn scoped_participants_do_not_collapse_equal_node_ids() {
    let config = CeremonyConfig {
        current: committee(&[("old-a", "peer-old-a", 1), ("overlap", "peer-o", 2)], 1),
        next: Some(committee(
            &[("new-a", "peer-new-a", 1), ("overlap", "peer-o", 2)],
            1,
        )),
    };
    assert_ne!(ParticipantRef::current(1), ParticipantRef::next(1));
    assert_eq!(config.node_key(ParticipantRef::current(1)), Some("old-a"));
    assert_eq!(config.node_key(ParticipantRef::next(1)), Some("new-a"));
    assert_eq!(
        config.union_routes().len(),
        3,
        "overlap must deduplicate by node key"
    );
}

#[test]
fn activation_digest_binds_frozen_current_dealers() {
    let base = [7; 32];
    let first = activation_digest(
        base,
        &[ParticipantRef::current(1), ParticipantRef::current(2)],
    )
    .unwrap();
    let reordered = activation_digest(
        base,
        &[ParticipantRef::current(2), ParticipantRef::current(1)],
    )
    .unwrap();
    let different = activation_digest(base, &[ParticipantRef::current(1)]).unwrap();
    assert_eq!(first, reordered);
    assert_ne!(first, different);
    assert!(activation_digest(base, &[ParticipantRef::next(1)]).is_err());
}

#[test]
fn configuration_digest_survives_a_fifty_member_wire_round_trip() {
    let node_keys: Vec<String> = (0..50).map(|index| format!("node-{index:02}")).collect();
    let peer_routes: Vec<String> = (0..50).map(|index| format!("peer-{index:02}")).collect();
    let node_id_assignments: HashMap<String, u32> = node_keys
        .iter()
        .rev()
        .enumerate()
        .map(|(index, key)| (key.clone(), 50 - index as u32))
        .collect();
    let mut prepare = PrepareSession {
        ceremony_id: CeremonyId(99),
        attempt_id: AttemptId([7; 32]),
        config_digest: [0; 32],
        topic_id: [8; 32],
        leader_node_key: node_keys[0].clone(),
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys,
                peer_routes,
                node_id_assignments,
                threshold: 34,
            },
            next: None,
        },
        kind: SessionKind::Fresh,
        pss_interval: 60,
        policy_id: Some("policy".into()),
        ring_id: "ring".into(),
        report_signature: None,
    };
    prepare.config_digest = config_digest(&prepare).unwrap();

    let wire = encode(&prepare).unwrap();
    let decoded: PrepareSession = decode(&wire, wire.len()).unwrap();

    assert_eq!(config_digest(&decoded).unwrap(), prepare.config_digest);
}

#[test]
fn committee_configuration_rejects_more_than_fifty_members_on_either_side() {
    let node_keys: Vec<_> = (1..=51).map(|node_id| format!("node-{node_id}")).collect();
    let oversized = CommitteeConfig {
        peer_routes: (1..=51).map(|node_id| format!("peer-{node_id}")).collect(),
        node_id_assignments: node_keys
            .iter()
            .enumerate()
            .map(|(index, key)| (key.clone(), index as u32 + 1))
            .collect(),
        node_keys,
        threshold: 34,
    };
    let valid = committee(&[("node-a", "peer-a", 1)], 1);

    let error = CeremonyConfig {
        current: oversized.clone(),
        next: None,
    }
    .validate()
    .expect_err("the current committee must be capped");
    assert!(error.contains("current committee has 51 members"));

    let error = CeremonyConfig {
        current: valid,
        next: Some(oversized),
    }
    .validate()
    .expect_err("the next committee must be capped");
    assert!(error.contains("next committee has 51 members"));
}

#[test]
fn public_repair_cursor_fields_round_trip() {
    let request = DkgControlMessage::GetPublicPhase {
        ceremony_id: CeremonyId(4),
        attempt_id: AttemptId([5; 32]),
        phase: PublicPhase::Commitments,
        after: Some(ParticipantRef::current(7)),
    };
    let encoded = encode(&request).unwrap();
    assert_eq!(
        decode::<DkgControlMessage>(&encoded, encoded.len()).unwrap(),
        request
    );

    let response = DkgControlMessage::PublicPhaseResponse {
        ceremony_id: CeremonyId(4),
        attempt_id: AttemptId([5; 32]),
        phase: PublicPhase::Commitments,
        contributions: vec![network::SignedPayload {
            origin: vec![1; 32],
            signature: vec![2; 64],
            data: vec![3; 128],
        }],
        next_cursor: Some(ParticipantRef::current(8)),
        page_digest: [9; 32],
        report_signature: Some(ControlSignature {
            signer_node_key: "leader".to_string(),
            signed_at: 1_700_000_000,
            signature: vec![4; 64],
        }),
    };
    let encoded = encode(&response).unwrap();
    assert_eq!(
        decode::<DkgControlMessage>(&encoded, encoded.len()).unwrap(),
        response
    );
}

#[test]
fn reshare_pair_owner_uses_node_keys_and_pair_hello_is_scoped() {
    let config = CeremonyConfig {
        current: committee(&[("z-dealer", "peer-z", 1)], 1),
        next: Some(committee(&[("a-receiver", "peer-a", 1)], 1)),
    };
    let dealer = ParticipantRef::current(1);
    let receiver = ParticipantRef::next(1);
    assert_eq!(
        config.canonical_pair_opener(dealer, receiver),
        Some(receiver),
        "numeric node IDs must not choose a reshare opener"
    );
    let ceremony = CeremonyId(4);
    let attempt = AttemptId([5; 32]);
    let pair_id = derive_pair_hello_id(ceremony, attempt, receiver, dealer);
    assert_eq!(
        pair_id,
        derive_pair_hello_id(ceremony, attempt, receiver, dealer)
    );
    assert_ne!(
        pair_id,
        derive_pair_hello_id(ceremony, attempt, dealer, receiver)
    );
}

#[test]
fn committee_and_leader_are_order_independent() {
    let a = vec!["node-c".into(), "node-a".into(), "node-b".into()];
    let b = vec!["node-b".into(), "node-c".into(), "node-a".into()];
    assert_eq!(canonical_leader(&a), Some("node-a"));
    assert_eq!(committee_digest(&a), committee_digest(&b));
}

#[test]
fn reshare_leader_is_canonical_next_receiver_and_is_digest_bound() {
    let mut prepare = PrepareSession {
        ceremony_id: CeremonyId(42),
        attempt_id: AttemptId([3; 32]),
        config_digest: [0; 32],
        topic_id: [4; 32],
        leader_node_key: "new-a".into(),
        committees: CeremonyConfig {
            current: committee(&[("old-a", "peer-old-a", 1), ("old-b", "peer-old-b", 2)], 2),
            next: Some(committee(
                &[("new-b", "peer-new-b", 2), ("new-a", "peer-new-a", 1)],
                2,
            )),
        },
        kind: SessionKind::Reshare {
            ring_pk_hex: "ring-pk".into(),
            new_peer_node_keys: vec!["new-a".into(), "new-b".into()],
            new_threshold: 2,
            bulletin_post_id: "ring".into(),
        },
        pss_interval: 60,
        policy_id: Some("policy".into()),
        ring_id: "ring".into(),
        report_signature: None,
    };
    assert_eq!(prepare.canonical_leader_node_key(), Some("new-a"));
    assert_eq!(prepare.leader_route(), Some("peer-new-a"));

    let next_leader_digest = config_digest(&prepare).unwrap();
    prepare.leader_node_key = "old-a".into();
    assert_ne!(config_digest(&prepare).unwrap(), next_leader_digest);
    assert_ne!(
        prepare.canonical_leader_node_key(),
        Some(prepare.leader_node_key.as_str())
    );
}

#[test]
fn topic_and_message_ids_isolate_attempts() {
    let committee = committee_digest(&["node-a".into(), "node-b".into()]);
    let ceremony = CeremonyId(7);
    let first = AttemptId([1; 32]);
    let second = AttemptId([2; 32]);
    assert_ne!(
        derive_topic_id("chain", "ring", &committee, ceremony, first),
        derive_topic_id("chain", "ring", &committee, ceremony, second)
    );
    let payload = DkgPublicPayload::CommitmentHash {
        commitment_hash: [9; 32],
    };
    let origin = ParticipantRef::current(1);
    assert_ne!(
        derive_message_id(
            ceremony,
            first,
            PublicPhase::CommitmentHashes,
            origin,
            None,
            &payload
        )
        .unwrap(),
        derive_message_id(
            ceremony,
            second,
            PublicPhase::CommitmentHashes,
            origin,
            None,
            &payload
        )
        .unwrap()
    );
}

#[test]
fn public_message_type_cannot_encode_a_share() {
    let message = DkgPublicMessage::TopologyProbe {
        ceremony_id: CeremonyId(1),
        attempt_id: AttemptId([2; 32]),
        nonce: [3; 32],
    };
    let encoded = encode(&message).unwrap();
    let decoded: DkgPublicMessage = decode(&encoded, 1024).unwrap();
    assert_eq!(message, decoded);

    let private = DkgPrivateMessage::Busy {
        ceremony_id: CeremonyId(1),
        attempt_id: AttemptId([2; 32]),
        retry_after_ms: 100,
    };
    let encoded_private = encode(&private).unwrap();
    assert!(decode::<DkgPublicMessage>(&encoded_private, 1024).is_err());
}

#[test]
fn lower_node_id_is_the_only_pair_opener() {
    assert!(is_canonical_pair_opener(1, 2));
    assert!(!is_canonical_pair_opener(2, 1));
    assert!(!is_canonical_pair_opener(2, 2));
}

#[test]
fn contribution_rejects_payload_mutation() {
    let mut contribution = DkgPublicContribution::new(
        CeremonyId(1),
        AttemptId([2; 32]),
        "ring".into(),
        [3; 32],
        ParticipantRef::current(4),
        DkgPublicPayload::CommitmentHash {
            commitment_hash: [5; 32],
        },
    )
    .unwrap();
    contribution.payload = DkgPublicPayload::CommitmentHash {
        commitment_hash: [6; 32],
    };
    assert!(contribution.validate_message_id().is_err());
}

#[test]
fn contribution_message_id_binds_explicit_signing_time() {
    let mut contribution = DkgPublicContribution::new_at(
        CeremonyId(1),
        AttemptId([2; 32]),
        "ring".into(),
        [3; 32],
        ParticipantRef::current(4),
        1_700_000_000,
        DkgPublicPayload::CommitmentHash {
            commitment_hash: [5; 32],
        },
    )
    .unwrap();
    let message_id = contribution.message_id;
    assert!(contribution.validate_message_id().is_ok());

    contribution.signed_at += 1;
    assert!(contribution.validate_message_id().is_err());

    let reconstructed = DkgPublicContribution::new_at(
        CeremonyId(1),
        AttemptId([2; 32]),
        "ring".into(),
        [3; 32],
        ParticipantRef::current(4),
        1_700_000_000,
        DkgPublicPayload::CommitmentHash {
            commitment_hash: [5; 32],
        },
    )
    .unwrap();
    assert_eq!(reconstructed.message_id, message_id);
}

#[test]
fn phase_root_is_canonical_and_attempt_scoped() {
    let ceremony = CeremonyId(11);
    let attempt = AttemptId([12; 32]);
    let first = BTreeMap::from([
        (ParticipantRef::current(2), MessageId([2; 32])),
        (ParticipantRef::current(1), MessageId([1; 32])),
    ]);
    let second = BTreeMap::from([
        (ParticipantRef::current(1), MessageId([1; 32])),
        (ParticipantRef::current(2), MessageId([2; 32])),
    ]);
    assert_eq!(
        phase_root(ceremony, attempt, PublicPhase::Commitments, &first),
        phase_root(ceremony, attempt, PublicPhase::Commitments, &second)
    );
    assert_ne!(
        phase_root(ceremony, attempt, PublicPhase::Commitments, &first),
        phase_root(
            ceremony,
            AttemptId([13; 32]),
            PublicPhase::Commitments,
            &first
        )
    );
}

#[test]
fn scoped_participant_map_keys_round_trip_on_the_json_wire() {
    let ceremony = CeremonyId(14);
    let attempt = AttemptId([15; 32]);
    let contribution_ids = BTreeMap::from([
        (ParticipantRef::current(1), MessageId([1; 32])),
        (ParticipantRef::next(1), MessageId([2; 32])),
    ]);
    let message = DkgPublicMessage::Manifest(PhaseManifest {
        ceremony_id: ceremony,
        attempt_id: attempt,
        phase: PublicPhase::Commitments,
        phase_root: phase_root(
            ceremony,
            attempt,
            PublicPhase::Commitments,
            &contribution_ids,
        ),
        contribution_ids,
        chunk_count: 1,
        complete: true,
        signed_at: 1_700_000_000,
    });

    let encoded = encode(&message).unwrap();
    let decoded: DkgPublicMessage = decode(&encoded, encoded.len()).unwrap();

    assert_eq!(decoded, message);
    let text = String::from_utf8(encoded).unwrap();
    assert!(text.contains("current:1"));
    assert!(text.contains("next:1"));
}

#[test]
fn manifest_rejects_omission_and_invalid_root() {
    let ceremony = CeremonyId(21);
    let attempt = AttemptId([22; 32]);
    let ids = BTreeMap::from([
        (ParticipantRef::current(1), MessageId([1; 32])),
        (ParticipantRef::current(2), MessageId([2; 32])),
    ]);
    let mut manifest = PhaseManifest {
        ceremony_id: ceremony,
        attempt_id: attempt,
        phase: PublicPhase::Commitments,
        phase_root: phase_root(ceremony, attempt, PublicPhase::Commitments, &ids),
        contribution_ids: ids,
        chunk_count: 1,
        complete: true,
        signed_at: 1_700_000_000,
    };
    let committee = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
    assert!(manifest.validate(&committee).is_ok());

    manifest
        .contribution_ids
        .remove(&ParticipantRef::current(2));
    assert!(manifest.validate(&committee).is_err());
    manifest
        .contribution_ids
        .insert(ParticipantRef::current(2), MessageId([2; 32]));
    manifest.phase_root = [99; 32];
    assert!(manifest.validate(&committee).is_err());
    manifest.phase_root = phase_root(
        ceremony,
        attempt,
        PublicPhase::Commitments,
        &manifest.contribution_ids,
    );
    manifest.chunk_count = 3;
    assert!(
        manifest.validate(&committee).is_err(),
        "a non-empty chunk cannot outnumber committed contributions"
    );
}

#[test]
fn chunks_use_canonical_order_and_actual_encoded_limit() {
    let contributions = BTreeMap::from([
        (
            ParticipantRef::current(3),
            network::SignedPayload {
                origin: vec![3],
                signature: vec![3; 64],
                data: vec![3; 256],
            },
        ),
        (
            ParticipantRef::current(1),
            network::SignedPayload {
                origin: vec![1],
                signature: vec![1; 64],
                data: vec![1; 256],
            },
        ),
        (
            ParticipantRef::current(2),
            network::SignedPayload {
                origin: vec![2],
                signature: vec![2; 64],
                data: vec![2; 256],
            },
        ),
    ]);
    let limit = 1_500;
    let chunks = chunk_public_contributions_with_limit(
        CeremonyId(1),
        AttemptId([2; 32]),
        PublicPhase::Commitments,
        [3; 32],
        contributions,
        1_700_000_000,
        limit,
    )
    .unwrap();

    assert!(chunks.len() > 1);
    let mut origins = Vec::new();
    for (expected_index, chunk) in chunks.iter().enumerate() {
        assert!(encode(chunk).unwrap().len() <= limit);
        let DkgPublicMessage::Chunk {
            index,
            contributions,
            ..
        } = chunk
        else {
            panic!("chunk helper returned a non-chunk message");
        };
        assert_eq!(*index, expected_index as u32);
        origins.extend(contributions.iter().map(|signed| signed.origin[0]));
    }
    assert_eq!(origins, vec![1, 2, 3]);
}

#[test]
fn private_message_id_binds_recipient_and_exact_share() {
    let ceremony = CeremonyId(1);
    let attempt = AttemptId([2; 32]);
    let nonce = [3; 16];
    let from = ParticipantRef::current(1);
    let to = ParticipantRef::current(2);
    let original = derive_private_message_id(ceremony, attempt, from, to, &[4, 5], &nonce);
    assert_eq!(
        original,
        derive_private_message_id(ceremony, attempt, from, to, &[4, 5], &nonce)
    );
    assert_ne!(
        original,
        derive_private_message_id(
            ceremony,
            attempt,
            from,
            ParticipantRef::current(3),
            &[4, 5],
            &nonce,
        )
    );
    assert_ne!(
        original,
        derive_private_message_id(ceremony, attempt, from, to, &[4, 6], &nonce)
    );
}
