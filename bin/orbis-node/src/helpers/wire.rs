//! Binary wire codec for point-to-point PRE and Sign protocol frames.
//!
//! Replaces `serde_json` on the `reencrypt` and `sign` ALPNs. JSON renders a
//! `Vec<u8>` as a decimal array (`[0,255,17,...]`), ~2-4 bytes per source byte,
//! so a maximal 1 MiB [`crate::sign::v0::messages::SignRequest`] `message`
//! inflated to 2-4 MiB and was rejected by the receiving
//! [`crate::constants::NETWORK_MAX_MESSAGE_SIZE`] — every such request, though
//! accepted by the gRPC API, failed at the peer boundary.
//!
//! MessagePack via [`rmp_serde::to_vec_named`] keeps byte fields 1:1 while
//! encoding structs as field-named maps, so it preserves `serde_json`'s exact
//! handling of `#[serde(default)]` / `skip_serializing_if` across the reporting
//! and bulletin types reachable from [`crate::sign::v0::messages::SignContext`].
//! It is self-describing, so a schema skew between node builds surfaces as a
//! clean decode error rather than silent corruption.
//!
//! DKG keeps its own JSON [`crate::dkg::v0::transport`] codec: that encoding
//! also feeds canonical hashing for threshold-signed evidence and must stay
//! byte-stable.

use serde::{de::DeserializeOwned, Serialize};

/// Serialize a point-to-point protocol message to its MessagePack wire form.
pub(crate) fn encode<T>(value: &T) -> Result<Vec<u8>, rmp_serde::encode::Error>
where
    T: Serialize + ?Sized,
{
    rmp_serde::to_vec_named(value)
}

/// Deserialize a point-to-point protocol message from its MessagePack wire form.
///
/// The caller is responsible for bounding `bytes`; inbound frames are already
/// capped at [`crate::constants::NETWORK_MAX_MESSAGE_SIZE`] by the network
/// layer before they reach here.
pub(crate) fn decode<T>(bytes: &[u8]) -> Result<T, rmp_serde::decode::Error>
where
    T: DeserializeOwned,
{
    rmp_serde::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct WithBytes {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        payload: Vec<u8>,
    }

    #[test]
    fn round_trips_and_keeps_bytes_one_to_one() {
        let msg = WithBytes {
            id: "req-1".to_string(),
            note: None,
            payload: vec![0u8; 4096],
        };
        let encoded = encode(&msg).expect("encode");
        // JSON would be well over 8 KiB for this; MessagePack stays ~ payload len.
        assert!(encoded.len() < msg.payload.len() + 128);
        let decoded: WithBytes = decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn absent_skipped_field_decodes_to_default() {
        let encoded = encode(&WithBytes {
            id: "req-2".to_string(),
            note: None,
            payload: vec![1, 2, 3],
        })
        .expect("encode");
        let decoded: WithBytes = decode(&encoded).expect("decode");
        assert_eq!(decoded.note, None);
    }
}
