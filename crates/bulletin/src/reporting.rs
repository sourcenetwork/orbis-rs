//! Canonical ring-state projection used by report signers.

use crate::r#trait::RingPayload;
use orbis_reporting::codec::{
    write_bool, write_optional_string, write_optional_string_vec, write_optional_u32,
    write_optional_u64, write_string, write_string_vec, write_u32, write_u64,
};
use sha2::{Digest, Sha256};

pub fn ring_state_sha256(payload: &RingPayload) -> String {
    hex::encode(Sha256::digest(canonical_ring_state_bytes(payload)))
}

pub fn canonical_ring_state_bytes(payload: &RingPayload) -> Vec<u8> {
    let mut out = Vec::new();
    write_string(&mut out, &payload.ring_pk);
    write_string_vec(&mut out, &payload.peer_node_keys);
    write_u32(&mut out, payload.threshold);

    write_optional_string_vec(&mut out, payload.new_peer_node_keys.as_deref());
    write_optional_u32(&mut out, payload.new_threshold);
    write_u64(&mut out, payload.pss_interval);
    write_u64(&mut out, payload.block_number_nonce);
    write_optional_string(&mut out, payload.policy_id.as_deref());
    write_bool(&mut out, payload.trusted_auth_relay_dids.is_some());
    write_string_vec(
        &mut out,
        payload
            .trusted_auth_relay_dids
            .as_deref()
            .unwrap_or_default(),
    );
    write_u64(&mut out, payload.upgrade_info.current_version);
    write_optional_u64(&mut out, payload.upgrade_info.next_version);
    write_optional_u64(&mut out, payload.upgrade_info.activation_time);
    write_reporting_config(&mut out, &payload.reporting);
    out
}

/// Field order matches the proto declaration order and is the canonical
/// wire contract — the chain-side (Go) decoder must read fields in
/// exactly this order.
fn write_demerit_config(out: &mut Vec<u8>, value: &crate::r#trait::DemeritConfig) {
    write_u64(out, value.node_offline_demerits);
    write_u64(out, value.reset_interval_seconds);
    write_u64(out, value.invalid_crypto_response_demerits);
    write_u64(out, value.unauthorized_request_demerits);
}

fn write_reporting_config(out: &mut Vec<u8>, value: &crate::r#trait::ReportingConfig) {
    write_demerit_config(out, &value.demerit_config);
    write_string_vec(out, &value.backup_node_keys);
    write_u64(out, value.kick_threshold);
}

#[cfg(test)]
mod tests {
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
}
