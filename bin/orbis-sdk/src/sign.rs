//! Sign: threshold-signing requests.

use authn::{create_authenticated_request, endpoints::sign::SignClaims};
use orbis_integration_core::{CanonicalOperation, SignOperation};
use proto::v0::sign::sign_service_client::SignServiceClient;
use proto::v0::sign::{StartSignRequest, TimestampRange};
use sha2::{Digest, Sha256};

use crate::client::OrbisClient;
use crate::error::{Result, SdkError};
#[cfg(feature = "webauthn")]
use crate::evidence::{ChallengeEvidence, WireEvidence};
use crate::identity::JwtIdentitySigner;
use crate::jwt::{now_unix, sign_jwt, JWT_TTL};

/// Result of a Sign operation.
#[derive(Debug, Clone)]
pub struct SignResult {
    pub status: String,
    pub message: String,
    pub created_at: i64,
    pub signature: String,
}

/// Everything about a Sign request that's fixed before authorization
/// evidence exists — built by [`build_sign_challenge`], consumed by
/// [`OrbisClient::submit_sign_with_evidence`]. Splitting this out (mirroring
/// PRE's own `PendingPre`) is what lets a real evidence ceremony (a browser
/// WebAuthn prompt, say) run in between: the challenge it must embed has to
/// be decided before the evidence exists, but the request can't be
/// submitted until after.
///
/// The JWT path has no such split — a [`JwtIdentitySigner`] mints its own
/// token synchronously, with no external ceremony to wait on — so
/// [`OrbisClient::submit_sign_with_jwt`] takes its inputs directly instead.
#[cfg_attr(not(feature = "webauthn"), allow(dead_code))]
pub struct PendingSign {
    operation: SignOperation,
    derivation_id: String,
    message: Vec<u8>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
}

impl PendingSign {
    /// The exact bytes a challenge-based evidence ceremony must embed as
    /// its challenge — recomputed, not stored, since it's a pure function
    /// of the other fields.
    pub fn challenge(&self) -> Vec<u8> {
        self.operation.canonical_bytes()
    }

    /// Builds the [`orbis_webauthn::PasskeyAssertion`] evidence for this
    /// pending challenge from a raw WebAuthn assertion a ceremony against
    /// [`PendingSign::challenge`] produced.
    ///
    /// `expiry`/`nonce` are pulled from the exact values this challenge
    /// committed to, not freely chosen — an evidence value declaring
    /// different ones wouldn't match what the WebAuthn signature actually
    /// covers, and would fail verification. `issued_at` genuinely is free
    /// to choose fresh here: Sign's own protocol doesn't cryptographically
    /// bind it the way PRE's reader-key proof-of-possession does (see
    /// `proto::v0::sign::WebAuthnAssertion`'s own doc comment).
    #[cfg(feature = "webauthn")]
    pub fn passkey_evidence(
        &self,
        issuer_did: impl Into<String>,
        assertion: orbis_webauthn::RawAssertion,
    ) -> Result<orbis_webauthn::PasskeyAssertion> {
        Ok(orbis_webauthn::PasskeyAssertion {
            issuer_did: issuer_did.into(),
            assertion,
            issued_at: now_unix()?,
            expiry: self.operation.expiry,
            nonce: self.operation.nonce,
        })
    }
}

/// Builds a Sign challenge: a fresh `issued_at`/`expiry`/nonce bound to
/// `derivation_id` and `message`'s digest, canonically encoded
/// ([`SignOperation::canonical_bytes`]). The node independently recomputes
/// and compares this same encoding, so nothing here needs to be remembered
/// by this crate between this call and
/// [`OrbisClient::submit_sign_with_evidence`] — only by whoever drives the
/// evidence ceremony in between.
pub fn build_sign_challenge(
    derivation_id: impl Into<String>,
    message: Vec<u8>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Result<PendingSign> {
    let derivation_id = derivation_id.into();
    let issued_at = now_unix()?;
    let expiry = issued_at + 300;
    let nonce: [u8; 16] = rand::random();
    let operation = SignOperation {
        derivation_id: derivation_id.clone(),
        message_sha256: Sha256::digest(&message).to_vec(),
        expiry,
        nonce,
    };
    Ok(PendingSign {
        operation,
        derivation_id,
        message,
        valid_window_start,
        valid_window_end,
    })
}

impl OrbisClient {
    /// Calls `SignService.StartSign` with a JWT-authenticated request.
    /// `derivation_id` must match the `KeyDerivation` posted to the
    /// bulletin (an admin/chain operation, out of this crate's scope) —
    /// the JWT is bound to it so the node can verify the caller is
    /// authorized to sign under that key derivation.
    pub async fn submit_sign_with_jwt(
        &self,
        message: Vec<u8>,
        derivation_id: impl Into<String>,
        signer: &impl JwtIdentitySigner,
        valid_window_start: Option<u64>,
        valid_window_end: Option<u64>,
    ) -> Result<SignResult> {
        let derivation_id = derivation_id.into();
        let claims = SignClaims {
            derivation_id: derivation_id.clone(),
            message_sha256: Sha256::digest(&message).to_vec(),
        };
        let (token, _metadata) = sign_jwt(signer, claims, JWT_TTL)?;

        let mut client = SignServiceClient::new(self.channel());
        let request = StartSignRequest {
            message,
            derivation_id,
            valid_window: valid_window(valid_window_start, valid_window_end),
            webauthn_assertion: None,
        };
        let tonic_request = create_authenticated_request(request, &token)
            .map_err(|e| SdkError::Crypto(format!("failed to attach JWT: {e}")))?;

        let response = client.start_sign(tonic_request).await?.into_inner();
        Ok(SignResult {
            status: response.status,
            message: response.message,
            created_at: response.created_at,
            signature: response.signature,
        })
    }

    /// Calls `SignService.StartSign` with evidence produced for
    /// `pending`'s challenge. `derivation_id` must have been granted (via
    /// ACP) to the identity `evidence` authenticates as; there is no
    /// separate enrollment step.
    #[cfg(feature = "webauthn")]
    pub async fn submit_sign_with_evidence<E>(
        &self,
        pending: PendingSign,
        evidence: E,
    ) -> Result<SignResult>
    where
        E: ChallengeEvidence<SignOperation>,
        E::Wire: Into<WireEvidence>,
    {
        let wire: WireEvidence = evidence
            .produce(&pending.operation)
            .map_err(|e| SdkError::Evidence(e.to_string()))?
            .into();

        let mut client = SignServiceClient::new(self.channel());
        let request = StartSignRequest {
            message: pending.message,
            derivation_id: pending.derivation_id,
            valid_window: valid_window(pending.valid_window_start, pending.valid_window_end),
            webauthn_assertion: Some(wire.into_sign_assertion()),
        };
        let response = client
            .start_sign(tonic::Request::new(request))
            .await?
            .into_inner();
        Ok(SignResult {
            status: response.status,
            message: response.message,
            created_at: response.created_at,
            signature: response.signature,
        })
    }
}

fn valid_window(start: Option<u64>, end: Option<u64>) -> Option<TimestampRange> {
    match (start, end) {
        (Some(start), Some(end)) => Some(TimestampRange { start, end }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sign_challenge_is_deterministic_for_the_same_operation() {
        let pending = build_sign_challenge("deriv-1", b"hello".to_vec(), None, None).unwrap();
        // The challenge is a pure function of `pending`'s own fields.
        assert_eq!(pending.challenge(), pending.operation.canonical_bytes());
    }

    #[test]
    fn build_sign_challenge_differs_for_different_messages() {
        let a = build_sign_challenge("deriv-1", b"hello".to_vec(), None, None).unwrap();
        let b = build_sign_challenge("deriv-1", b"goodbye".to_vec(), None, None).unwrap();
        assert_ne!(a.challenge(), b.challenge());
    }
}
