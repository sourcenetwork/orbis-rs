//! Passkey-authorized signing: verifies a [`WebAuthnEvidence`] and produces
//! the same `BearerToken<SignClaims>` shape the JWT path already produces,
//! so every downstream check (actor resolution, ACP, single-use enforcement
//! via `jwt_id`, relay attribution) runs unchanged regardless of which
//! authentication method was used.
//!
//! Must be called independently by every participating node (the service
//! entry point *and* each peer's own re-check in `coordinator::handlers`) —
//! never trust a coordinator's claim that this already passed.

use crate::sign::v0::error::SignError;
use crate::sign::v0::messages::WebAuthnEvidence;
use authn::{BearerToken, SignClaims};
use orbis_integration_core::SignOperation;
use orbis_webauthn::{verify_assertion, RawAssertion};

/// Converts the wire-level proto assertion into the internal, serde-able
/// evidence carried through [`crate::sign::v0::messages::PolicyContext`].
pub(crate) fn evidence_from_proto(
    assertion: proto::v0::sign::WebAuthnAssertion,
) -> WebAuthnEvidence {
    WebAuthnEvidence {
        issuer_did: assertion.issuer_did,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
        expiry: assertion.expiry,
        nonce: assertion.nonce,
    }
}

/// Verifies `evidence` against this exact request (`derivation_id` +
/// `message_sha256`) and this node's configured relying-party ID/origin,
/// and returns a synthetic `BearerToken<SignClaims>` on success.
///
/// Takes the message's digest rather than the raw message: FROST's Round 1
/// (`handle_nonce_request`) has no message bytes to hash yet, only
/// `PolicyContext::message_sha256` computed once at stage 1 — unlike the
/// JWT path, WebAuthn verification can't defer this to Round 2, since the
/// expected challenge (and so the signature check itself) depends on it.
///
/// `rp_id`/`origin` being absent (node not configured for passkey signing)
/// is a hard rejection, not a silent fallback.
pub(crate) fn verify_and_build_token(
    evidence: &WebAuthnEvidence,
    derivation_id: &str,
    message_sha256: &[u8],
    rp_id: Option<&str>,
    origin: Option<&str>,
    current_time: u64,
) -> Result<BearerToken<SignClaims>, SignError> {
    let (rp_id, origin) = match (rp_id, origin) {
        (Some(rp_id), Some(origin)) => (rp_id, origin),
        _ => {
            return Err(SignError::Unauthorized(
                "WebAuthn-authorized signing is not configured on this node".to_string(),
            ))
        }
    };

    if current_time > evidence.expiry {
        return Err(SignError::Unauthorized(
            "WebAuthn evidence has expired".to_string(),
        ));
    }

    let nonce: [u8; 16] = evidence.nonce.as_slice().try_into().map_err(|_| {
        SignError::Unauthorized("WebAuthn evidence nonce must be 16 bytes".to_string())
    })?;

    let operation = SignOperation {
        derivation_id: derivation_id.to_string(),
        message_sha256: message_sha256.to_vec(),
        expiry: evidence.expiry,
        nonce,
    };

    let credential_public_key = authn::p256_public_key_from_did(&evidence.issuer_did)
        .map_err(|e| SignError::Unauthorized(format!("invalid issuer_did: {e}")))?;

    let raw_assertion = RawAssertion {
        authenticator_data: evidence.authenticator_data.clone(),
        client_data_json: evidence.client_data_json.clone(),
        signature: evidence.signature.clone(),
    };

    verify_assertion(
        &credential_public_key,
        &raw_assertion,
        rp_id,
        origin,
        &operation.canonical_bytes(),
    )
    .map_err(|e| SignError::Unauthorized(format!("WebAuthn verification failed: {e}")))?;

    Ok(BearerToken {
        issuer_id: evidence.issuer_did.clone(),
        subject_id: None,
        issued_time: current_time,
        expiration_time: evidence.expiry,
        not_before: None,
        jwt_id: hex::encode(&evidence.nonce),
        claims: SignClaims {
            derivation_id: derivation_id.to_string(),
            message_sha256: message_sha256.to_vec(),
        },
    })
}
