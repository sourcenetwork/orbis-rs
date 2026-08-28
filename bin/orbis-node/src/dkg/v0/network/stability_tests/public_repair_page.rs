#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn public_phase_repair_pages_are_bounded_complete_and_canonical() {
    let retained: BTreeMap<_, _> = (1u8..=MAX_DKG_COMMITTEE_SIZE as u8)
        .rev()
        .map(|node_id| {
            (
                ParticipantRef::current(node_id as u32),
                retained_repair_contribution(node_id, 30_000),
            )
        })
        .collect();
    let ceremony_id = CeremonyId(777);
    let attempt_id = AttemptId([8; 32]);
    let mut after = None;
    let mut received = Vec::new();
    let mut page_count = 0;

    loop {
        let response = public_phase_response_page(
            ceremony_id,
            attempt_id,
            PublicPhase::Commitments,
            &retained,
            after,
        )
        .unwrap();
        assert!(
            transport::encode(&response).unwrap().len() <= transport::MAX_PUBLIC_REPAIR_PAGE_BYTES
        );
        let DkgControlMessage::PublicPhaseResponse {
            contributions,
            next_cursor,
            ..
        } = response
        else {
            panic!("repair helper returned the wrong response type");
        };
        page_count += 1;
        received.extend(contributions.into_iter().map(|signed| signed.origin[0]));
        let Some(cursor) = next_cursor else {
            break;
        };
        assert!(after.is_none_or(|previous| cursor > previous));
        after = Some(cursor);
    }

    assert!(page_count > 1);
    assert!(page_count <= MAX_DKG_COMMITTEE_SIZE);
    assert_eq!(
        received,
        (1u8..=MAX_DKG_COMMITTEE_SIZE as u8).collect::<Vec<_>>()
    );

    let terminal = public_phase_response_page(
        ceremony_id,
        attempt_id,
        PublicPhase::Commitments,
        &retained,
        Some(ParticipantRef::current(MAX_DKG_COMMITTEE_SIZE as u32)),
    )
    .unwrap();
    assert!(matches!(
        terminal,
        DkgControlMessage::PublicPhaseResponse {
            contributions,
            next_cursor: None,
            ..
        } if contributions.is_empty()
    ));
}

#[test]
fn public_phase_repair_rejects_one_oversized_contribution() {
    let retained = BTreeMap::from([(
        ParticipantRef::current(1),
        retained_repair_contribution(1, transport::MAX_PUBLIC_REPAIR_PAGE_BYTES / 2),
    )]);
    let error = public_phase_response_page(
        CeremonyId(778),
        AttemptId([9; 32]),
        PublicPhase::Commitments,
        &retained,
        None,
    )
    .expect_err("one contribution cannot exceed the repair page limit");
    assert!(matches!(error, DkgError::ProtocolError(_)));
}

#[test]
fn public_repair_page_progress_rejects_cursor_and_origin_contradictions() {
    let empty = BTreeSet::new();
    assert!(validate_public_repair_page_progress(
        Some(ParticipantRef::current(1)),
        &[ParticipantRef::current(2), ParticipantRef::current(3)],
        Some(ParticipantRef::current(3)),
        &empty,
    )
    .is_ok());
    assert!(validate_public_repair_page_progress(
        None,
        &[],
        Some(ParticipantRef::current(1)),
        &empty,
    )
    .is_err());
    assert!(validate_public_repair_page_progress(
        Some(ParticipantRef::current(2)),
        &[ParticipantRef::current(2)],
        None,
        &empty,
    )
    .is_err());
    assert!(validate_public_repair_page_progress(
        None,
        &[ParticipantRef::current(2), ParticipantRef::current(1)],
        None,
        &empty,
    )
    .is_err());
    assert!(validate_public_repair_page_progress(
        None,
        &[ParticipantRef::current(1), ParticipantRef::current(2)],
        Some(ParticipantRef::current(1)),
        &empty,
    )
    .is_err());
    assert!(validate_public_repair_page_progress(
        Some(ParticipantRef::current(1)),
        &[ParticipantRef::current(2)],
        None,
        &BTreeSet::from([ParticipantRef::current(2)]),
    )
    .is_err());
}
