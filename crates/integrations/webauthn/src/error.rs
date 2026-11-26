//! Error types for [`crate::verify_assertion`] (wire-level checks) and
//! [`crate::verify_and_build_token`]/[`crate::verify_endpoint_auth`] (the
//! higher-level authentication path built on top of it).

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed authenticatorData")]
    MalformedAuthenticatorData,
    #[error("malformed clientDataJSON: {0}")]
    MalformedClientData(String),
    #[error("unexpected clientDataJSON.type: {0}")]
    UnexpectedType(String),
    #[error("clientDataJSON.challenge did not match the expected operation")]
    ChallengeMismatch,
    #[error("clientDataJSON.origin did not match the expected origin")]
    OriginMismatch,
    #[error(
        "clientDataJSON indicates a cross-origin (framed) ceremony, which this RP does not accept"
    )]
    CrossOriginNotAllowed,
    #[error("authenticatorData rpIdHash did not match the expected RP ID")]
    RpIdMismatch,
    #[error("authenticatorData's User Present flag was not set")]
    UserNotPresent,
    #[error("invalid P-256 public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    SignatureInvalid,
}

#[derive(Debug, thiserror::Error)]
pub enum WebAuthnAuthError {
    #[error("WebAuthn-authorized requests are not configured on this node")]
    NotConfigured,
    #[error("WebAuthn evidence has expired")]
    Expired,
    #[error("WebAuthn evidence's validity period exceeds the maximum this node allows")]
    LifetimeTooLong,
    #[error("WebAuthn evidence nonce must be 16 bytes")]
    InvalidNonce,
    #[error("invalid issuer_did: {0}")]
    InvalidIssuerDid(String),
    #[error("WebAuthn verification failed: {0}")]
    Verification(#[from] VerifyError),
}
