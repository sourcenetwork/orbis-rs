//! PRE: proxy re-encryption (decrypt) requests.

use authn::{create_authenticated_request, endpoints::pre::PreClaims};
use crypto::context::{CiphertextContext, ReaderAuthorizationContext, ValidWindowBinding};
use crypto::r#trait::{Secret, ThresholdDealer};
use crypto::{
    CryptoDeserialize, CryptoSerialize, GroupAffine as G1Affine, PreImpl as ThresholdDealerNode,
    ScalarField as Fr,
};
use orbis_integration_core::{CanonicalOperation, PreOperation};
use proto::v0::pre::pre_service_client::PreServiceClient;
use proto::v0::pre::{InlineDocument, StartPreRequest, TimestampRange};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::client::OrbisClient;
use crate::error::{Result, SdkError};
#[cfg(any(feature = "webauthn", feature = "email"))]
use crate::evidence::{ChallengeEvidence, WireEvidence};
use crate::identity::JwtIdentitySigner;
use crate::jwt::{now_unix, sign_jwt, JWT_TTL};

/// Response structure from the PRE server (JSON in
/// `StartPreResponse.encrypted_secret`). Mirrors `orbis-node`'s own
/// `coordinator::PreReencryptResponse` wire shape — kept as an independent
/// shadow type rather than a dependency on `orbis-node` (the wrong
/// dependency direction).
#[derive(Debug, Clone, Serialize, Deserialize)]
enum PreResponse {
    Direct(Box<DirectPreResponse>),
    /// The ring's `pre_share_endpoints` delivery mode.
    Stored {
        manifest: Box<pre_share::PreShareRetrievalManifest>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirectPreResponse {
    /// Recovered reencrypted commitment (xnc_cmt) as hex string.
    xnc_cmt: String,
    secret: Secret,
    context: CiphertextContext,
}

/// Everything about a PRE request that's fixed before authorization
/// evidence exists — built by [`build_pre_challenge`], consumed by
/// [`OrbisClient::submit_pre_with_evidence`]. The ephemeral reader keypair
/// is generated here, not at submit time: the challenge embeds `rdr_pk`, so
/// it has to exist before the challenge can even be built.
///
/// Deliberately not generated-and-persisted anywhere by this crate beyond
/// this one in-memory value: whoever drives the evidence ceremony in
/// between (e.g. a browser) holds it, in whatever way they choose, until
/// [`OrbisClient::submit_pre_with_evidence`] consumes it.
#[cfg_attr(not(any(feature = "webauthn", feature = "email")), allow(dead_code))]
pub struct PendingPre {
    reader_sk_scalar: Fr,
    reader_pk_point: G1Affine,
    reader_pk_bytes: Vec<u8>,
    reader_auth_context: ReaderAuthorizationContext,
    object_id: String,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
    ring_pk_bytes: Vec<u8>,
    issued_at: u64,
    expiry: u64,
    nonce: [u8; 16],
}

// Manual impl, mirroring the convention `crypto::r#trait::types` already
// uses for every struct holding a raw secret scalar (`PriShare`,
// `DistKeyShare`, `ReencryptReply`, ...): letting this drop normally would
// leave the ephemeral reader's decryption key sitting in freed-but-unzeroed
// memory for however long this process keeps running afterward — a real
// exposure window for a long-lived server, not something "the process will
// exit eventually" excuses.
impl Drop for PendingPre {
    fn drop(&mut self) {
        self.reader_sk_scalar.zeroize();
    }
}

impl PendingPre {
    /// The exact bytes a challenge-based evidence ceremony must embed as
    /// its challenge — recomputed, not stored, since it's a pure function
    /// of the other fields.
    pub fn challenge(&self) -> Vec<u8> {
        PreOperation {
            object_id: self.object_id.clone(),
            rdr_pk: self.reader_pk_bytes.clone(),
            derivation: self.derivation.clone(),
            salt: self.salt.clone(),
            issued_at: self.issued_at,
            expiry: self.expiry,
            nonce: self.nonce,
        }
        .canonical_bytes()
    }

    /// The exact text a challenge email must ask the reader to read,
    /// approve, and reply to verbatim — recomputed, not stored, same as
    /// [`PendingPre::challenge`]. See
    /// `orbis_email::challenge_text`/`orbis_integration_core::CanonicalDisplay`
    /// for why this is a separate, human-legible rendering rather than the
    /// binary bytes [`PendingPre::challenge`] returns.
    #[cfg(feature = "email")]
    pub fn email_challenge_text(&self) -> String {
        orbis_email::challenge_text(&PreOperation {
            object_id: self.object_id.clone(),
            rdr_pk: self.reader_pk_bytes.clone(),
            derivation: self.derivation.clone(),
            salt: self.salt.clone(),
            issued_at: self.issued_at,
            expiry: self.expiry,
            nonce: self.nonce,
        })
    }

    /// Builds the [`orbis_webauthn::PasskeyAssertion`] evidence for this
    /// pending challenge from a raw WebAuthn assertion a ceremony against
    /// [`PendingPre::challenge`] produced.
    ///
    /// Unlike Sign, all three of `issued_at`/`expiry`/`nonce` are pulled
    /// from the exact values this challenge committed to, never freely
    /// chosen: PRE's reader-key proof-of-possession signature was already
    /// computed against this exact `issued_at` (see
    /// [`build_pre_challenge`]'s own doc comment), so an evidence value
    /// declaring a different one would make the server's independently
    /// reconstructed transcript diverge from what that signature covers.
    #[cfg(feature = "webauthn")]
    pub fn passkey_evidence(
        &self,
        issuer_did: impl Into<String>,
        assertion: orbis_webauthn::RawAssertion,
    ) -> orbis_webauthn::PasskeyAssertion {
        orbis_webauthn::PasskeyAssertion {
            issuer_did: issuer_did.into(),
            assertion,
            issued_at: self.issued_at,
            expiry: self.expiry,
            nonce: self.nonce,
        }
    }

    /// Builds the [`orbis_email::SignedEmailAssertion`] evidence for this
    /// pending challenge from an already-captured, DKIM-signed reply whose
    /// body contains this challenge's exact text
    /// ([`PendingPre::email_challenge_text`]). Same binding note as
    /// [`PendingPre::passkey_evidence`] applies: all three of
    /// `issued_at`/`expiry`/`nonce` are pulled from the exact values this
    /// challenge committed to.
    #[cfg(feature = "email")]
    pub fn email_evidence(
        &self,
        claimed_address: impl Into<String>,
        raw_message: Vec<u8>,
    ) -> orbis_email::SignedEmailAssertion {
        orbis_email::SignedEmailAssertion {
            claimed_address: claimed_address.into(),
            raw_message,
            issued_at: self.issued_at,
            expiry: self.expiry,
            nonce: self.nonce,
        }
    }
}

/// Builds everything about a PRE request that doesn't depend on the
/// authorization evidence itself — including generating the fresh
/// ephemeral reader keypair every PRE request needs (see
/// [`PendingPre`]'s own doc comment on why a fresh key per request is
/// non-negotiable: reusing a recipient key across requests lets an
/// attacker who authored one ciphertext and observes two PRE responses
/// recover `sR` from one and peel it off the other to decrypt it). Call
/// [`PendingPre::challenge`] on the result to get the bytes an evidence
/// ceremony's challenge must embed, then pass both to
/// [`OrbisClient::submit_pre_with_evidence`] once that ceremony produces
/// evidence.
#[allow(clippy::too_many_arguments)]
pub fn build_pre_challenge(
    chain_id: String,
    ring_pk: String,
    object_id: String,
    issuer_did: &str,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Result<PendingPre> {
    let (reader_sk_scalar, reader_pk_point) = crypto::helpers::generate_keypair()
        .map_err(|e| SdkError::Crypto(format!("failed to generate reader keypair: {e}")))?;
    let reader_pk_bytes = CryptoSerialize::to_bytes(&reader_pk_point)
        .map_err(|e| SdkError::Encoding(format!("failed to serialize reader public key: {e}")))?;

    let issued_at = now_unix()?;
    let expiry = issued_at + 300;
    let nonce: [u8; 16] = rand::random();

    let ring_pk_bytes = hex::decode(&ring_pk)
        .map_err(|e| SdkError::Encoding(format!("failed to decode ring_pk hex: {e}")))?;
    let valid_window_binding = match (valid_window_start, valid_window_end) {
        (Some(start), Some(end)) => Some(ValidWindowBinding { start, end }),
        _ => None,
    };
    let reader_auth_context = ReaderAuthorizationContext {
        chain_id,
        ring_pk: ring_pk_bytes.clone(),
        jwt_issuer: issuer_did.to_string(),
        jwt_subject: None,
        resolved_actor: issuer_did.to_string(),
        jwt_id: hex::encode(nonce),
        jwt_issued_time: issued_at,
        jwt_expiration_time: expiry,
        jwt_not_before: None,
        object_id: object_id.clone(),
        recipient_pk: reader_pk_bytes.clone(),
        derivation: derivation.clone(),
        salt: salt.clone(),
        valid_window: valid_window_binding,
        audit_target_object_id: None,
    };

    Ok(PendingPre {
        reader_sk_scalar,
        reader_pk_point,
        reader_pk_bytes,
        reader_auth_context,
        object_id,
        derivation,
        salt,
        valid_window_start,
        valid_window_end,
        ring_pk_bytes,
        issued_at,
        expiry,
        nonce,
    })
}

/// A PRE request's wire response plus everything the reader needs to
/// decrypt it *later*, independently of this process — returned by
/// [`OrbisClient::submit_pre_with_jwt_and_hold`] instead of decrypting
/// immediately. `reader_sk_hex` is the ephemeral reader secret key that
/// call generated for this one request; losing it means the response can
/// never be decrypted, by design.
#[derive(Serialize, Deserialize)]
pub struct PendingPreRetrieval {
    reader_sk_hex: String,
    ring_pk: String,
    derivation: Option<Vec<u8>>,
    response: PreResponse,
}

// Manual impl (rather than derive), matching `crypto::r#trait::types`'s own
// convention for any type holding a raw secret: `Serialize` deliberately
// exposes `reader_sk_hex` (serializing this out is the whole point of the
// save-now/decrypt-later path), but a log or panic message printing this
// value via `{:?}` would leak the reader's decryption key for no reason —
// those are different concerns.
impl std::fmt::Debug for PendingPreRetrieval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPreRetrieval")
            .field("reader_sk_hex", &"[REDACTED]")
            .field("ring_pk", &self.ring_pk)
            .field("derivation", &self.derivation)
            .field("response", &self.response)
            .finish()
    }
}

impl OrbisClient {
    /// Calls `PreService.StartPre` with a JWT-authenticated request, and
    /// decrypts the result locally. `document`/`audit_target_object_id`
    /// let a caller supply the document inline (instead of reading it from
    /// the bulletin) and name the ACP object PET should audit ownership
    /// against — both default to `None` for the common case.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_pre_with_jwt(
        &self,
        chain_id: String,
        ring_pk: String,
        object_id: String,
        signer: &impl JwtIdentitySigner,
        derivation: Option<Vec<u8>>,
        salt: Option<String>,
        valid_window_start: Option<u64>,
        valid_window_end: Option<u64>,
        document: Option<InlineDocument>,
        audit_target_object_id: Option<String>,
    ) -> Result<Vec<u8>> {
        let (response, reader_sk_scalar, ring_pk_bytes) = self
            .request_pre_with_jwt(
                chain_id,
                ring_pk,
                object_id,
                signer,
                derivation.clone(),
                salt,
                valid_window_start,
                valid_window_end,
                document,
                audit_target_object_id,
            )
            .await?;
        decrypt_pre_response(
            response,
            reader_sk_scalar,
            &ring_pk_bytes,
            derivation.as_deref(),
        )
        .await
    }

    /// Same request as [`OrbisClient::submit_pre_with_jwt`], but doesn't
    /// decrypt — returns a [`PendingPreRetrieval`] the caller can serialize
    /// and decrypt later via [`retrieve_pre`], independently of this
    /// process.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_pre_with_jwt_and_hold(
        &self,
        chain_id: String,
        ring_pk: String,
        object_id: String,
        signer: &impl JwtIdentitySigner,
        derivation: Option<Vec<u8>>,
        salt: Option<String>,
        valid_window_start: Option<u64>,
        valid_window_end: Option<u64>,
    ) -> Result<PendingPreRetrieval> {
        let (response, reader_sk_scalar, _ring_pk_bytes) = self
            .request_pre_with_jwt(
                chain_id,
                ring_pk.clone(),
                object_id,
                signer,
                derivation.clone(),
                salt,
                valid_window_start,
                valid_window_end,
                None,
                None,
            )
            .await?;
        let reader_sk_hex =
            hex::encode(CryptoSerialize::to_bytes(&reader_sk_scalar).map_err(|e| {
                SdkError::Encoding(format!("failed to serialize reader secret key: {e}"))
            })?);
        Ok(PendingPreRetrieval {
            reader_sk_hex,
            ring_pk,
            derivation,
            response,
        })
    }

    /// Calls `PreService.StartPre` with evidence produced for `pending`'s
    /// challenge, and decrypts the result locally. `object_id`'s document's
    /// policy must have granted the right permission to the identity
    /// `evidence` authenticates as; there is no separate enrollment step.
    #[cfg(any(feature = "webauthn", feature = "email"))]
    pub async fn submit_pre_with_evidence<E>(
        &self,
        pending: PendingPre,
        evidence: E,
    ) -> Result<Vec<u8>>
    where
        E: ChallengeEvidence<PreOperation>,
        E::Wire: Into<WireEvidence>,
    {
        let wire: WireEvidence = evidence
            .produce(&PreOperation {
                object_id: pending.object_id.clone(),
                rdr_pk: pending.reader_pk_bytes.clone(),
                derivation: pending.derivation.clone(),
                salt: pending.salt.clone(),
                issued_at: pending.issued_at,
                expiry: pending.expiry,
                nonce: pending.nonce,
            })
            .map_err(|e| SdkError::Evidence(e.to_string()))?
            .into();
        let (webauthn_assertion, email_assertion) = wire.into_pre_assertion();

        let rdr_pk_signature = ThresholdDealerNode::sign_reader_authorization(
            &pending.reader_sk_scalar,
            &pending.reader_pk_point,
            &pending.reader_auth_context,
        )
        .map_err(|e| SdkError::Crypto(format!("failed to sign reader authorization: {e}")))?;

        let mut client = PreServiceClient::new(self.channel());
        let request = StartPreRequest {
            rdr_pk: pending.reader_pk_bytes.clone(),
            object_id: pending.object_id.clone(),
            derivation: pending.derivation.clone(),
            salt: pending.salt.clone(),
            valid_window: valid_window(pending.valid_window_start, pending.valid_window_end),
            document: None,
            rdr_pk_signature: Some(proto::v0::pre::ReaderAuthorizationSignature {
                challenge: rdr_pk_signature.challenge,
                response: rdr_pk_signature.response,
            }),
            audit_target_object_id: None,
            webauthn_assertion,
            email_assertion,
        };

        let response = client
            .start_pre(tonic::Request::new(request))
            .await?
            .into_inner();
        let pre_response = parse_pre_response(response.encrypted_secret)?;

        decrypt_pre_response(
            pre_response,
            pending.reader_sk_scalar,
            &pending.ring_pk_bytes,
            pending.derivation.as_deref(),
        )
        .await
    }

    /// Runs the on-wire part of a JWT-authenticated PRE request — ephemeral
    /// reader keypair, JWT, signed reader-authorization transcript, the
    /// actual `StartPre` call — and returns the parsed response plus the
    /// reader's own secret scalar and the decoded ring public key bytes.
    /// Shared by [`OrbisClient::submit_pre_with_jwt`] (decrypts
    /// immediately) and [`OrbisClient::submit_pre_with_jwt_and_hold`]
    /// (saves for later).
    #[allow(clippy::too_many_arguments)]
    async fn request_pre_with_jwt(
        &self,
        chain_id: String,
        ring_pk: String,
        object_id: String,
        signer: &impl JwtIdentitySigner,
        derivation: Option<Vec<u8>>,
        salt: Option<String>,
        valid_window_start: Option<u64>,
        valid_window_end: Option<u64>,
        document: Option<InlineDocument>,
        audit_target_object_id: Option<String>,
    ) -> Result<(PreResponse, Fr, Vec<u8>)> {
        // Step 1: always a fresh ephemeral reader keypair — see
        // `build_pre_challenge`'s doc comment for why reuse is unsafe.
        let (reader_sk_scalar, reader_pk_point) = crypto::helpers::generate_keypair()
            .map_err(|e| SdkError::Crypto(format!("failed to generate reader keypair: {e}")))?;
        let reader_pk_bytes = CryptoSerialize::to_bytes(&reader_pk_point).map_err(|e| {
            SdkError::Encoding(format!("failed to serialize reader public key: {e}"))
        })?;

        // Step 2: mint the JWT, carrying its jti/timestamps forward to the
        // reader-authorization transcript below instead of discarding them.
        let claims = PreClaims {
            rdr_pk: reader_pk_bytes.clone(),
            object_id: object_id.clone(),
            derivation: derivation.clone(),
            salt: salt.clone(),
        };
        let (token, token_metadata) = sign_jwt(signer, claims, JWT_TTL)?;

        // Step 3: build the request-bound transcript and sign it with the
        // reader key. The node independently rebuilds the identical
        // context server-side and verifies this signature before touching
        // any share.
        let ring_pk_bytes = hex::decode(&ring_pk)
            .map_err(|e| SdkError::Encoding(format!("failed to decode ring_pk hex: {e}")))?;
        let valid_window_binding = match (valid_window_start, valid_window_end) {
            (Some(start), Some(end)) => Some(ValidWindowBinding { start, end }),
            _ => None,
        };
        let reader_auth_context = ReaderAuthorizationContext {
            chain_id,
            ring_pk: ring_pk_bytes.clone(),
            jwt_issuer: signer.did().to_string(),
            jwt_subject: None,
            resolved_actor: signer.did().to_string(),
            jwt_id: token_metadata.jwt_id,
            jwt_issued_time: token_metadata.issued_time,
            jwt_expiration_time: token_metadata.expiration_time,
            jwt_not_before: token_metadata.not_before,
            object_id: object_id.clone(),
            recipient_pk: reader_pk_bytes.clone(),
            derivation: derivation.clone(),
            salt: salt.clone(),
            valid_window: valid_window_binding,
            audit_target_object_id: audit_target_object_id.clone(),
        };
        let rdr_pk_signature = ThresholdDealerNode::sign_reader_authorization(
            &reader_sk_scalar,
            &reader_pk_point,
            &reader_auth_context,
        )
        .map_err(|e| SdkError::Crypto(format!("failed to sign reader authorization: {e}")))?;

        // Step 4: send to the PRE service for re-encryption.
        let mut client = PreServiceClient::new(self.channel());
        let request = StartPreRequest {
            rdr_pk: reader_pk_bytes,
            object_id,
            derivation: derivation.clone(),
            salt,
            valid_window: valid_window(valid_window_start, valid_window_end),
            document,
            rdr_pk_signature: Some(proto::v0::pre::ReaderAuthorizationSignature {
                challenge: rdr_pk_signature.challenge,
                response: rdr_pk_signature.response,
            }),
            audit_target_object_id,
            webauthn_assertion: None,
            email_assertion: None,
        };
        let tonic_request = create_authenticated_request(request, &token)
            .map_err(|e| SdkError::Crypto(format!("failed to attach JWT: {e}")))?;

        let response = client.start_pre(tonic_request).await?.into_inner();
        let pre_response = parse_pre_response(response.encrypted_secret)?;
        Ok((pre_response, reader_sk_scalar, ring_pk_bytes))
    }
}

/// Decrypts a [`PendingPreRetrieval`] saved by
/// [`OrbisClient::submit_pre_with_jwt_and_hold`] — the deferred half of the
/// save-now/retrieve-later path, independent of the process that made the
/// original request. Takes no [`OrbisClient`]: everything needed either
/// already traveled in `pending` or (for the `Stored` delivery mode) is
/// fetched directly from Defra, never from orbis-node itself.
pub async fn retrieve_pre(pending: PendingPreRetrieval) -> Result<Vec<u8>> {
    let mut reader_sk_bytes = hex::decode(&pending.reader_sk_hex)
        .map_err(|e| SdkError::Encoding(format!("failed to decode reader secret key hex: {e}")))?;
    let reader_sk_scalar = Fr::from_bytes(&reader_sk_bytes)
        .map_err(|e| SdkError::Encoding(format!("failed to deserialize reader secret key: {e}")));
    reader_sk_bytes.zeroize();
    let reader_sk_scalar = reader_sk_scalar?;
    let ring_pk_bytes = hex::decode(&pending.ring_pk)
        .map_err(|e| SdkError::Encoding(format!("failed to decode ring_pk hex: {e}")))?;

    decrypt_pre_response(
        pending.response,
        reader_sk_scalar,
        &ring_pk_bytes,
        pending.derivation.as_deref(),
    )
    .await
}

fn parse_pre_response(encrypted_secret: Vec<u8>) -> Result<PreResponse> {
    if encrypted_secret.is_empty() {
        return Err(SdkError::Rejected(
            "PRE response did not contain encrypted_secret".to_string(),
        ));
    }
    serde_json::from_slice(&encrypted_secret)
        .map_err(|e| SdkError::Encoding(format!("failed to parse PRE response: {e}")))
}

/// Step 5 of a PRE request: decrypt a parsed [`PreResponse`], handling both
/// delivery modes. `Direct` decrypts immediately with its own
/// `xnc_cmt`/`secret`/`context`. `Stored` fetches, verifies, and recovers
/// via `pre_share::recover_from_manifest` first — an empty Defra bearer
/// token (anonymous read) is deliberate, see that function's own doc
/// comment on why — then uses the *recovered* `derivation` (pulled from
/// the manifest's own independently-verified entries) rather than the
/// caller-supplied one, since it's already authenticated and is the actual
/// value every responder computed its share under.
async fn decrypt_pre_response(
    pre_response: PreResponse,
    reader_sk_scalar: Fr,
    ring_pk_bytes: &[u8],
    derivation: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Zeroized on every exit (including the early `?` returns below), not
    // just after a successful decrypt — a `Zeroizing` guard runs on drop
    // regardless of which path leaves the function.
    let reader_sk_scalar = zeroize::Zeroizing::new(reader_sk_scalar);

    let (xnc_cmt, secret, context, effective_derivation) = match pre_response {
        PreResponse::Direct(direct) => {
            let xnc_cmt_bytes = hex::decode(&direct.xnc_cmt)
                .map_err(|e| SdkError::Encoding(format!("failed to decode xnc_cmt hex: {e}")))?;
            let xnc_cmt = G1Affine::from_bytes(&xnc_cmt_bytes)
                .map_err(|e| SdkError::Encoding(format!("failed to deserialize xnc_cmt: {e}")))?;
            (
                xnc_cmt,
                direct.secret,
                direct.context,
                derivation.map(|d| d.to_vec()),
            )
        }
        PreResponse::Stored { manifest } => {
            let recovered = pre_share::recover_from_manifest(&manifest, "")
                .await
                .map_err(|e| {
                    SdkError::Rejected(format!("failed to recover Defra-stored PRE shares: {e}"))
                })?;
            (
                recovered.xnc_cmt,
                manifest.secret,
                manifest.context,
                recovered.derivation,
            )
        }
    };

    let ring_pk_point = G1Affine::from_bytes(ring_pk_bytes)
        .map_err(|e| SdkError::Encoding(format!("failed to deserialize ring_pk: {e}")))?;

    let effective_pk = if let Some(ref deriv) = effective_derivation {
        ThresholdDealerNode::derive_public_key(&ring_pk_point, deriv)
            .map_err(|e| SdkError::Crypto(format!("failed to derive public key: {e}")))?
    } else {
        ring_pk_point
    };

    ThresholdDealerNode::decrypt_secret(
        &effective_pk,
        &xnc_cmt,
        &reader_sk_scalar,
        &secret,
        &context,
    )
    .map_err(|e| SdkError::Crypto(format!("decryption failed: {e}")))
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

    /// `PendingPreRetrieval`'s fields are private (an opaque resume token,
    /// matching the `prepared_json`-as-a-raw-string convention StoreSecret
    /// already uses) — so this builds one through its own
    /// `Serialize`/`Deserialize` shape via JSON, the same way
    /// `submit_pre_with_jwt_and_hold`'s caller and `retrieve_pre` do,
    /// rather than via struct-literal construction, which isn't available
    /// outside this module anyway.
    #[test]
    fn pending_pre_retrieval_roundtrips_through_json() {
        let json = serde_json::json!({
            "reader_sk_hex": "aabbcc",
            "ring_pk": "ring-pk-hex",
            "derivation": null,
            "response": {
                "Direct": {
                    "xnc_cmt": "deadbeef",
                    "secret": {
                        "enc_cmt": [1, 2, 3],
                        "encrypted_data": [4, 5, 6],
                        "nonce": [7, 8, 9, 10, 11, 12]
                    },
                    "context": {
                        "ring_pk": [1, 2, 3],
                        "policy_id": "policy-1",
                        "resource": "resource",
                        "permission": "read",
                        "tier": null,
                        "timestamp": null,
                        "salt": null,
                        "pet_tag": null
                    }
                }
            }
        })
        .to_string();

        let pending: PendingPreRetrieval = serde_json::from_str(&json).expect("deserialize");
        let round_tripped_json = serde_json::to_string(&pending).expect("serialize");
        let round_tripped: PendingPreRetrieval =
            serde_json::from_str(&round_tripped_json).expect("deserialize again");

        // `Debug` redacts `reader_sk_hex` (see its own impl's doc comment),
        // so check it survives the round trip directly rather than relying
        // on the `Debug` comparison below to catch a mismatch there.
        assert_eq!(pending.reader_sk_hex, round_tripped.reader_sk_hex);
        assert_eq!(format!("{:?}", pending), format!("{:?}", round_tripped));
    }

    #[test]
    fn pending_pre_retrieval_debug_redacts_the_reader_secret_key() {
        let pending = PendingPreRetrieval {
            reader_sk_hex: "supersecrethex".to_string(),
            ring_pk: "ring-pk-hex".to_string(),
            derivation: None,
            response: PreResponse::Direct(Box::new(DirectPreResponse {
                xnc_cmt: "deadbeef".to_string(),
                secret: serde_json::from_value(serde_json::json!({
                    "enc_cmt": [1, 2, 3],
                    "encrypted_data": [4, 5, 6],
                    "nonce": [7, 8, 9, 10, 11, 12]
                }))
                .expect("deserialize Secret"),
                context: serde_json::from_value(serde_json::json!({
                    "ring_pk": [1, 2, 3],
                    "policy_id": "policy-1",
                    "resource": "resource",
                    "permission": "read",
                    "tier": null,
                    "timestamp": null,
                    "salt": null,
                    "pet_tag": null
                }))
                .expect("deserialize CiphertextContext"),
            })),
        };

        let debug = format!("{pending:?}");
        assert!(!debug.contains("supersecrethex"), "got: {debug}");
        assert!(debug.contains("[REDACTED]"), "got: {debug}");
    }
}
