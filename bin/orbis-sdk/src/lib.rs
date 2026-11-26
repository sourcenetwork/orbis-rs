//! Client SDK for integrating external applications with an Orbis ring:
//! Sign (threshold signing), PRE (proxy re-encryption / decrypt), and
//! StoreSecret (posting a locally-encrypted document), plus the local
//! cryptography and identity helpers those flows need.
//!
//! This crate never assumes how a caller creates or stores its secrets.
//! Long-lived identity keys are accepted through traits
//! ([`ChainIdentity`], [`JwtIdentitySigner`]) — a caller with its own key
//! custody (HSM, KMS, OS keychain) implements one directly and this crate
//! never receives, generates, or persists the private key itself. The one
//! exception is PRE's ephemeral reader keypair, which is deliberately
//! *not* behind either trait: it's protocol scaffolding generated fresh
//! per request, not a caller-owned credential — see [`pre::PendingPre`]'s
//! own doc comment.
//!
//! Authorization evidence comes in two shapes:
//! - A JWT, self-signed by a [`JwtIdentitySigner`] — `submit_*_with_jwt`.
//! - Evidence from an external authentication mechanism (WebAuthn today,
//!   via the `webauthn` feature; email/DKIM in the future), produced
//!   against an exact challenge via `orbis_integration_core::ChallengeEvidence`
//!   — `build_*_challenge` + `submit_*_with_evidence`.
//!
//! Everything here talks to one orbis-node endpoint through an
//! [`OrbisClient`].

mod client;
mod crypto;
mod dkg;
mod error;
#[cfg(feature = "webauthn")]
mod evidence;
mod identity;
mod jwt;
mod pre;
mod query;
mod sign;
mod store_secret;

pub use client::OrbisClient;
pub use crypto::{
    encrypt_secret, generate_pet_tag, prepare_secret, prove_pet_tag_knowledge, PreparedPetTag,
    PreparedSecret,
};
pub use dkg::DkgResult;
pub use error::{Result, SdkError};
#[cfg(feature = "webauthn")]
pub use evidence::{ChallengeEvidence, WireEvidence};
pub use identity::{
    derive_signer_did, reader_did_from_seed, secp256k1_pubkey_to_did, ChainIdentity,
    InMemoryChainIdentity, InMemoryEd25519Signer, JwtIdentitySigner,
};
pub use pre::{build_pre_challenge, retrieve_pre, PendingPre, PendingPreRetrieval};
pub use query::NodeInfoResult;
pub use sign::{build_sign_challenge, PendingSign, SignResult};
pub use store_secret::StoreSecretResult;
