use super::*;
use alloy_primitives::B256;
use vera_client::ClientError;

#[test]
fn submission_accepts_only_matching_id_or_exact_duplicate() {
    let id = B256::repeat_byte(7);
    assert!(accept_submission(Ok(id), id).is_ok());
    assert!(accept_submission(Ok(B256::repeat_byte(8)), id).is_err());
    assert!(accept_submission(
        Err(ClientError::Rpc {
            code: -32602,
            message: "invalid transaction: duplicate transaction".into(),
        }),
        id,
    )
    .is_ok());
    for (code, message) in [
        (-32000, "invalid transaction: duplicate transaction"),
        (-32602, "duplicate transaction"),
        (-32602, "invalid transaction: nonce too low"),
        (-32602, "invalid transaction: invalid signature"),
    ] {
        let failure = ClientError::Rpc {
            code,
            message: message.into(),
        };
        let expected = failure.to_string();
        assert_eq!(
            accept_submission(Err(failure), id).unwrap_err().to_string(),
            expected
        );
    }
    assert!(accept_submission(Err(ClientError::MissingResult), id).is_err());
}
