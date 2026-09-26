use super::*;
use crate::r#trait::UpgradeInfo;

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
