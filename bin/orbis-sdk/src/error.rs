//! The SDK's error type.

/// Everything that can go wrong calling into an Orbis ring through this
/// crate. Deliberately not a transparent wrapper around `anyhow`/`String`
/// everywhere: a library consumer should be able to match on the failure
/// mode (a rejected request vs. a transport problem vs. a local encoding
/// mistake) without parsing an error message.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    /// The gRPC call itself failed (connection, timeout, or the server
    /// returned a non-OK status).
    #[error("transport error: {0}")]
    Transport(#[from] tonic::Status),
    /// Failed to connect to the configured endpoint.
    #[error("failed to connect to {endpoint}: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: tonic::transport::Error,
    },
    /// A request succeeded at the transport level but the node rejected it
    /// (e.g. the response carried no payload, or an explicit failure
    /// status/message in the response body).
    #[error("request rejected: {0}")]
    Rejected(String),
    /// Malformed or unexpected data — hex/JSON decoding, an unparseable
    /// response body, a point that doesn't deserialize to a valid curve
    /// element, and the like.
    #[error("encoding error: {0}")]
    Encoding(String),
    /// A cryptographic operation itself failed (encryption, decryption, a
    /// proof that didn't verify, invalid key material).
    #[error("cryptographic error: {0}")]
    Crypto(String),
    /// A `ChallengeEvidence` producer failed to produce its evidence.
    #[error("evidence error: {0}")]
    Evidence(String),
    /// An argument was invalid on its face (e.g. a bad combination of
    /// optional fields), independent of any network or crypto operation.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, SdkError>;
