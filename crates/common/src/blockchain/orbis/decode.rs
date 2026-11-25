//! Decoding typed x/orbis responses out of Cosmos SDK ABCI broadcast results.

use super::types::{
    MsgCreateRingResponse, MsgStoreDocumentResponse, MsgStoreKeyDerivationResponse,
};
use prost::Message;

/// Minimal representation of google.protobuf.Any for decoding TxMsgData.
#[derive(Clone, prost::Message)]
struct AnyProto {
    #[prost(string, tag = "1")]
    pub type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

/// Cosmos SDK TxMsgData: wrapper around per-message ABCI responses.
/// Field 2 (msg_responses) is the modern SDK 0.46+ format.
/// Field 1 (data) is the legacy format; each entry's value bytes are
/// the raw-encoded response message.
#[derive(Clone, prost::Message)]
struct TxMsgData {
    #[prost(message, repeated, tag = "2")]
    pub msg_responses: Vec<AnyProto>,
}

/// Extract `MsgCreateRingResponse.ring_id` from a broadcast result.
///
/// Tries the modern Cosmos SDK format (TxMsgData.msg_responses) first,
/// then falls back to interpreting the raw data as `MsgCreateRingResponse`
/// directly. Returns `None` if decoding fails or the ring_id is empty.
pub fn decode_create_ring_id(data: Option<&Vec<u8>>) -> Option<String> {
    decode_tx_response_id::<MsgCreateRingResponse, _>(data, |resp| &resp.ring_id)
}

/// Extract `MsgStoreDocumentResponse.document_id` from a broadcast result.
pub fn decode_store_document_id(data: Option<&Vec<u8>>) -> Option<String> {
    decode_tx_response_id::<MsgStoreDocumentResponse, _>(data, |resp| &resp.document_id)
}

/// Extract `MsgStoreKeyDerivationResponse.key_derivation_id` from a broadcast result.
pub fn decode_store_key_derivation_id(data: Option<&Vec<u8>>) -> Option<String> {
    decode_tx_response_id::<MsgStoreKeyDerivationResponse, _>(data, |resp| &resp.key_derivation_id)
}

fn decode_tx_response_id<T, F>(data: Option<&Vec<u8>>, extract_id: F) -> Option<String>
where
    T: Message + Default,
    F: Fn(&T) -> &str,
{
    let bytes = data?;
    if bytes.is_empty() {
        return None;
    }

    // Try modern Cosmos SDK 0.46+ format: TxMsgData.msg_responses[0].value
    if let Ok(tx_data) = TxMsgData::decode(bytes.as_slice()) {
        for any in &tx_data.msg_responses {
            if let Ok(resp) = T::decode(any.value.as_slice()) {
                let id = extract_id(&resp);
                if !id.is_empty() {
                    return Some(id.to_string());
                }
            }
        }
    }

    // Fallback: try decoding the bytes directly as the response message.
    if let Ok(resp) = T::decode(bytes.as_slice()) {
        let id = extract_id(&resp);
        if !id.is_empty() {
            return Some(id.to_string());
        }
    }

    None
}
