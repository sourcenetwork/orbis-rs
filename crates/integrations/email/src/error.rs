//! Error types for [`crate::verify_email_message`] (wire-level/DKIM checks)
//! and [`crate::verify_and_build_token`]/[`crate::verify_endpoint_auth`]
//! (the higher-level authentication path built on top of it).

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed RFC 5322 message")]
    MalformedMessage,
    #[error("message carries no DKIM-Signature header")]
    NoSignature,
    #[error("no DKIM signature both verified and aligned with the From: domain")]
    NoAlignedPassingSignature,
    #[error("the expected operation's challenge text was not found in the message body")]
    TextNotFound,
    #[error("claimed_address did not match the DKIM-verified From address")]
    ClaimedAddressMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum EmailAuthError {
    #[error("email-authorized requests are not configured on this node")]
    NotConfigured,
    #[error("email evidence has expired")]
    Expired,
    #[error("email evidence's validity period exceeds the maximum this node allows")]
    LifetimeTooLong,
    #[error("email evidence nonce must be 16 bytes")]
    InvalidNonce,
    #[error("email verification failed: {0}")]
    Verification(#[from] VerifyError),
}
