#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn busy_and_local_private_failures_are_not_offline() {
    assert!(private_failure_is_unreachable(true, None));
    assert!(!private_failure_is_unreachable(
        true,
        Some(Duration::from_millis(10))
    ));
    assert!(!private_failure_is_unreachable(false, None));
    assert!(terminal_offline_candidate(true, false));
    assert!(
        !terminal_offline_candidate(true, true),
        "a prior Busy, error response, malformed response, or invalid ACK proves reachability"
    );
}

#[test]
fn offline_relay_claim_enforces_observer_role_and_canonical_candidates() {
    let committees = offline_relay_committees();
    let leader = PeerId::from_bytes(&[3; 32]);
    let follower = PeerId::from_bytes(&[4; 32]);
    let accused = [ParticipantRef::current(2)];

    validate_offline_relay_claim(
        &committees,
        "next-a",
        "current-a",
        &leader,
        PssOfflineStage::Prepare,
        &accused,
    )
    .expect("pure-new canonical leader may relay a preparation observation");
    assert!(validate_offline_relay_claim(
        &committees,
        "next-a",
        "current-a",
        &follower,
        PssOfflineStage::Prepare,
        &accused,
    )
    .is_err());
    validate_offline_relay_claim(
        &committees,
        "next-a",
        "current-a",
        &follower,
        PssOfflineStage::PrivatePair,
        &accused,
    )
    .expect("a pure-new participant may relay its own private-pair observation");
    validate_offline_relay_claim(
        &committees,
        "next-a",
        "current-a",
        &follower,
        PssOfflineStage::TopologyAck,
        &[ParticipantRef::next(1)],
    )
    .expect("a follower may report the unreachable canonical leader while returning an ACK");
    assert!(validate_offline_relay_claim(
        &committees,
        "next-a",
        "current-a",
        &follower,
        PssOfflineStage::TopologyAck,
        &accused,
    )
    .is_err());
    assert!(validate_offline_relay_claim(
        &committees,
        "next-a",
        "current-a",
        &leader,
        PssOfflineStage::StartForward,
        &accused,
    )
    .is_err());
    assert!(validate_offline_relay_claim(
        &committees,
        "next-a",
        "current-a",
        &leader,
        PssOfflineStage::Prepare,
        &[ParticipantRef::current(2), ParticipantRef::current(2)],
    )
    .is_err());
    assert!(validate_offline_relay_claim(
        &committees,
        "next-a",
        "current-a",
        &leader,
        PssOfflineStage::Prepare,
        &[ParticipantRef::current(99)],
    )
    .is_err());
}
