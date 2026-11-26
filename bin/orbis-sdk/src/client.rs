//! [`OrbisClient`]: a reusable connection to one orbis-node endpoint.
//!
//! Holding a `tonic::transport::Channel` instead of reconnecting per call —
//! the way both `cli-tool`'s commands and (independently) `passkey-sign`'s
//! own hand-rolled gRPC calls do today — is the one ergonomic change this
//! crate makes that has no real tradeoff against anything else in its
//! design. Each service's generated client is cheap to construct from a
//! cloned `Channel` per call (`Channel` is a lightweight handle, not a
//! fresh connection), so [`OrbisClient`]'s own methods — defined across
//! this crate's other modules — just do that.

use tonic::transport::Channel;

use crate::error::{Result, SdkError};

/// A connection to one orbis-node endpoint. Construct once per endpoint and
/// reuse — every operation this crate exposes is a method on this type.
pub struct OrbisClient {
    channel: Channel,
}

impl OrbisClient {
    /// Connects to `endpoint` (e.g. `http://127.0.0.1:50051`).
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self> {
        let endpoint = endpoint.into();
        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| SdkError::Encoding(format!("invalid endpoint {endpoint:?}: {e}")))?
            .connect()
            .await
            .map_err(|source| SdkError::Connect { endpoint, source })?;
        Ok(Self { channel })
    }

    /// A cheap clone of this client's underlying channel, for constructing
    /// one of orbis-node's generated per-service clients.
    pub(crate) fn channel(&self) -> Channel {
        self.channel.clone()
    }
}
