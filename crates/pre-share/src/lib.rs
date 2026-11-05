//! Signed PRE-share storage envelope and unsigned retrieval manifest for
//! Defra-backed PRE delivery (ring `pre_share_endpoints`).
//!
//! [`StoredShareEnvelope`]/[`SignedStoredShareEnvelope`] are what get signed
//! once and uploaded to Defra as document content. [`PreShareRetrievalManifest`]
//! is the relayer's own unsigned bookkeeping record of where each
//! participant's envelope landed, handed to the reader to independently
//! fetch and verify later. The stored-delivery acknowledgement a responder
//! returns to the relayer (`PreMessage::ReencryptStored`) is a P2P wire
//! message and stays with the rest of `orbis-node`'s `pre::v0::messages`,
//! not here — see that module.

mod envelope;
mod error;
mod manifest;

pub use envelope::*;
pub use error::*;
pub use manifest::*;
