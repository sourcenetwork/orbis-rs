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
mod tests;
