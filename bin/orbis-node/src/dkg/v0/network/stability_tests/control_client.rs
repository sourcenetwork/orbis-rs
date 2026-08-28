#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn peer_request_failure_preserves_reachability() {
    let unreachable = PeerRequestFailure::Unreachable(DkgError::NetworkConnection("down".into()));
    assert!(unreachable.is_unreachable());
    assert!(!unreachable.proves_reachable());
    let reachable = PeerRequestFailure::Reachable(DkgError::ProtocolError("bad ack".into()));
    assert!(!reachable.is_unreachable());
    assert!(reachable.proves_reachable());
    assert!(!PeerRequestFailure::Local(DkgError::Serialization("local".into())).is_unreachable());
}

#[test]
fn control_timeout_includes_operation_peer_and_attempt_scope() {
    let request = DkgControlMessage::TopologyProbeAck {
        ceremony_id: CeremonyId(42),
        attempt_id: AttemptId([7; 32]),
        nonce: [9; 32],
    };
    let message = control_timeout_message(
        "0123456789abcdef@127.0.0.1:9000",
        &request,
        PEER_RESPONSE_TIMEOUT,
    );
    assert!(message.contains("topology-probe-ack"));
    assert!(message.contains("0123456789ab"));
    assert!(message.contains("ceremony=42"));
    assert!(message.contains("attempt=070707070707"));
}
